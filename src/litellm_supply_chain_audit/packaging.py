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

    # On some hosts, dist-info / egg-info directories may be created with
    # unexpected casing (e.g. LiteLLM-...-dist-info). Use case-insensitive
    # matching to avoid missing installed versions.
    try:
        entries = list(site_packages.iterdir())
    except OSError:
        return files

    pkg = PACKAGE_NAME.casefold()

    for info_dir in entries:
        if not info_dir.is_dir():
            continue
        lowered = info_dir.name.casefold()

        # Per packaging's "recording installed projects" spec, `.dist-info` is
        # named `{name}-{version}.dist-info`, i.e. the separator between name
        # and version is always `-` (with additional normalization).
        if lowered.endswith(".dist-info") and lowered.startswith(pkg + "-"):
            meta = info_dir / "METADATA"
            if meta.is_file():
                files.append(meta)
            continue

        # `.egg-info` is legacy; different installers have historically used
        # either `{name}-{version}.egg-info` or `{name}.egg-info`.
        if lowered.endswith(".egg-info") and (
            lowered.startswith(pkg + "-") or lowered.startswith(pkg + ".")
        ):
            meta = info_dir / "PKG-INFO"
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
