"""Scan pip / uv download caches for compromised wheel/sdist names."""

import os
from pathlib import Path

from .constants import COMPROMISED_VERSIONS, PACKAGE_NAME


def _cache_roots() -> list[Path]:
    roots: list[Path] = []
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            roots.append(Path(local) / "pip" / "cache")
            roots.append(Path(local) / "uv" / "cache")
    home = Path.home()
    roots.extend(
        [
            home / ".cache" / "pip",
            home / ".cache" / "uv",
            home / "Library" / "Caches" / "pip",
            home / "Library" / "Caches" / "uv",
        ]
    )
    return [r for r in roots if r.is_dir()]


def _name_hits_bad_version(name: str) -> bool:
    lower = name.lower()
    if PACKAGE_NAME.lower() not in lower:
        return False
    return any(
        f"{PACKAGE_NAME}-{v}" in lower or f"{PACKAGE_NAME}_{v}" in lower
        for v in COMPROMISED_VERSIONS
    )


def scan_package_caches(max_files: int = 100_000) -> list[dict]:
    """Return cache file paths whose names suggest compromised litellm artifacts."""
    findings: list[dict] = []
    scanned = 0
    for root in _cache_roots():
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if scanned >= max_files:
                    return findings
                scanned += 1
                if _name_hits_bad_version(fn):
                    path = Path(dirpath) / fn
                    findings.append({"path": str(path), "filename": fn})
    return findings
