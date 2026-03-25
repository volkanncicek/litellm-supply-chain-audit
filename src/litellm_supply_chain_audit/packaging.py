"""Parse installed distribution metadata without importing packages."""

import re
from pathlib import Path

from .constants import PACKAGE_NAME

_VERSION_LINE = re.compile(r"^Version:\s*(.+)\s*$", re.MULTILINE)


def version_from_metadata_file(metadata_path: Path) -> str | None:
    try:
        text = metadata_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _VERSION_LINE.search(text)
    return m.group(1).strip() if m else None


def _iter_litellm_metadata_files(site_packages: Path) -> list[Path]:
    files: list[Path] = []
    for pattern, name in (
        (f"{PACKAGE_NAME}-*.dist-info", "METADATA"),
        (f"{PACKAGE_NAME}-*.egg-info", "PKG-INFO"),
    ):
        for info_dir in site_packages.glob(pattern):
            if not info_dir.is_dir():
                continue
            meta = info_dir / name
            if meta.is_file():
                files.append(meta)
    return files


def find_litellm_version_in_site_packages(site_packages: Path) -> str | None:
    """Return installed litellm version from dist/egg metadata, or None if not present."""
    if not site_packages.is_dir():
        return None
    for meta in _iter_litellm_metadata_files(site_packages):
        ver = version_from_metadata_file(meta)
        if ver:
            return ver
    return None


def has_requires_dist_litellm(metadata_path: Path) -> bool:
    """True if METADATA/PKG-INFO contains Requires-Dist: litellm."""
    try:
        text = metadata_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"(?im)^Requires-Dist:\s*litellm(?:[\s\[<>=!~,;]|$)", text))
