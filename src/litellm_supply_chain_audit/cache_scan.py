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
            # Common Poetry/Hatch cache locations on Windows.
            roots.append(Path(local) / "pypoetry" / "cache")
            roots.append(Path(local) / "pypoetry" / "artifacts")
            roots.append(Path(local) / "hatch" / "cache")
    home = Path.home()
    roots.extend(
        [
            home / ".cache" / "pip",
            home / ".cache" / "uv",
            # Poetry: wheel/sdist artifacts cached under pypoetry.
            home / ".cache" / "pypoetry",
            home / ".cache" / "pypoetry" / "artifacts",
            # Hatch: downloaded archives cached under hatch.
            home / ".cache" / "hatch",
            home / "Library" / "Caches" / "pip",
            home / "Library" / "Caches" / "uv",
            home / "Library" / "Caches" / "pypoetry",
            home / "Library" / "Caches" / "hatch",
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


def scan_package_caches(max_files: int = 100_000, max_hits: int = 200) -> list[dict]:
    """Return cache file paths whose names suggest compromised litellm artifacts.

    `max_files` is a hard cap for visited filenames; it is split across cache roots
    to avoid "one root dominates the budget" behavior.
    """
    findings: list[dict] = []
    roots = _cache_roots()
    if not roots or max_files <= 0:
        return findings

    per_root_budget = max(1, max_files // len(roots))
    global_hits = 0

    for root in roots:
        scanned_for_root = 0
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if global_hits >= max_hits:
                    return findings
                scanned_for_root += 1
                if scanned_for_root > per_root_budget:
                    break
                if _name_hits_bad_version(fn):
                    path = Path(dirpath) / fn
                    findings.append({"path": str(path), "filename": fn})
                    global_hits += 1
            if global_hits >= max_hits:
                return findings
            if scanned_for_root > per_root_budget:
                break

    return findings
