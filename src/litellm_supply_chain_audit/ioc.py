"""Search for malicious .pth IOC files."""

import os
import sys
from pathlib import Path

from .constants import (
    FS_WALK_SKIP_DIRS_COMMON,
    MALICIOUS_DOMAIN,
    PTH_IOC_NAME,
    SUPPORTED_PYTHON_MINOR_VERSIONS,
)


def _should_skip_dir(name: str) -> bool:
    extra = {
        ".npm",
        ".yarn",
        "Packages",
        "npm-cache",
        "yarn",
        "Temp",
    }
    return name in FS_WALK_SKIP_DIRS_COMMON or name in extra


def find_pth_in_site_packages(site_package_dirs: list[str], verbose: bool = False) -> list[dict]:
    """Fast IOC check: only `site-packages/litellm_init.pth` (typical install location)."""
    findings: list[dict] = []
    seen: set[str] = set()
    for raw in site_package_dirs:
        p = Path(raw) / PTH_IOC_NAME
        try:
            if not p.is_file():
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            snippet = _read_snippet(p)
            suspicious = MALICIOUS_DOMAIN in snippet
            findings.append(
                {
                    "path": key,
                    "suspicious_domain_present": suspicious,
                    "snippet_preview": snippet[:500],
                    "source": "site-packages",
                }
            )
        except OSError as e:
            if verbose:
                print(f"[pth-ioc] Skipped unreadable: {p} ({e})", file=sys.stderr)
            continue
    return findings


def find_litellm_init_pth(
    root: Path,
    max_depth: int = 4,
    max_hits: int = 50,
    verbose: bool = False,
) -> list[dict]:
    """
    Depth-limited search for `litellm_init.pth` under `root`.
    """
    findings: list[dict] = []
    root = root.resolve()

    def walk(cur: Path, depth: int) -> None:
        if len(findings) >= max_hits:
            return
        if depth > max_depth:
            return
        try:
            entries = list(cur.iterdir())
        except OSError as e:
            if verbose:
                print(f"[pth-ioc] Cannot access dir: {cur} ({e})", file=sys.stderr)
            return
        for p in entries:
            if len(findings) >= max_hits:
                return
            try:
                if p.is_dir():
                    if _should_skip_dir(p.name):
                        continue
                    walk(p, depth + 1)
                elif p.name == PTH_IOC_NAME:
                    snippet = _read_snippet(p)
                    suspicious = MALICIOUS_DOMAIN in snippet
                    findings.append(
                        {
                            "path": str(p),
                            "suspicious_domain_present": suspicious,
                            "snippet_preview": snippet[:500],
                        }
                    )
            except OSError as e:
                if verbose:
                    print(f"[pth-ioc] Skipped entry: {p} ({e})", file=sys.stderr)
                continue

    if root.is_dir():
        walk(root, 0)
    return findings


def _read_snippet(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def scan_hosts_file_for_ioc() -> dict:
    """Check OS hosts file for the known IOC domain."""
    if os.name == "nt":
        hosts = Path(r"C:\Windows\System32\drivers\etc\hosts")
    else:
        hosts = Path("/etc/hosts")
    try:
        text = hosts.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"status": "error", "path": str(hosts), "reason": str(e)}
    lines = [
        ln.strip()
        for ln in text.splitlines()
        if MALICIOUS_DOMAIN in ln and not ln.strip().startswith("#")
    ]
    return {"status": "ok", "path": str(hosts), "matched_lines": lines[:20]}


def find_pth_in_system_locations(max_hits: int = 50, verbose: bool = False) -> list[dict]:
    """
    Search common system Python locations for litellm_init.pth outside scan_root.
    """
    roots: list[Path] = []
    if os.name == "nt":
        versioned_roots = [Path(rf"C:\Python3{minor}") for minor in SUPPORTED_PYTHON_MINOR_VERSIONS]
        roots.extend(
            [
                *versioned_roots,
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python",
            ]
        )
    else:
        roots.extend([Path("/usr/lib"), Path("/usr/local/lib"), Path("/opt")])

    findings: list[dict] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for hit in find_litellm_init_pth(root, max_depth=6, max_hits=max_hits, verbose=verbose):
            path_key = str(hit.get("path", ""))
            if not path_key or path_key in seen:
                continue
            seen.add(path_key)
            hit["source"] = "system-locations"
            findings.append(hit)
            if len(findings) >= max_hits:
                return findings
    return findings
