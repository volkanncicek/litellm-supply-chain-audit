"""Scan site-packages trees for installed litellm versions."""

from __future__ import annotations

from pathlib import Path

from .constants import COMPROMISED_VERSIONS
from .packaging import find_litellm_version_in_site_packages, has_requires_dist_litellm


def scan_installed_in_environments(envs: list[dict]) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for env in envs:
        py = env.get("python", "")
        for sp in env.get("site_packages") or []:
            key = (py, sp)
            if key in seen:
                continue
            seen.add(key)
            p = Path(sp)
            ver = find_litellm_version_in_site_packages(p)
            if ver:
                findings.append(
                    {
                        "python": py,
                        "site_packages": str(p),
                        "litellm_version": ver,
                        "compromised": ver in COMPROMISED_VERSIONS,
                    }
                )
    return findings


def scan_indirect_dependency_in_environments(envs: list[dict]) -> list[dict]:
    """Find installed packages whose metadata declares Requires-Dist: litellm."""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for env in envs:
        py = env.get("python", "")
        for sp in env.get("site_packages") or []:
            root = Path(sp)
            if not root.is_dir():
                continue
            for info_dir in root.glob("*.dist-info"):
                if not info_dir.is_dir():
                    continue
                meta = info_dir / "METADATA"
                if not meta.is_file():
                    continue
                if not has_requires_dist_litellm(meta):
                    continue
                pkg = info_dir.name.removesuffix(".dist-info")
                key = (py, pkg)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({"python": py, "site_packages": str(root), "package": pkg})
    return findings
