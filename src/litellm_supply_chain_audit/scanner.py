"""Orchestrate all scan phases and compute exit code."""

import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .cache_scan import scan_package_caches
from .constants import (
    COMPROMISED_VERSIONS,
    MALICIOUS_DOMAIN,
    PRODUCT_NAME,
    remote_endpoint_matches_malicious_ioc,
)
from .dep_files import scan_dependency_files
from .discovery import discover_environments
from .docker_scan import scan_docker_images
from .installed import scan_indirect_dependency_in_environments, scan_installed_in_environments
from .ioc import (
    find_litellm_init_pth,
    find_pth_in_site_packages,
    find_pth_in_system_locations,
    scan_hosts_file_for_ioc,
)
from .processes import scan_processes_and_network


@dataclass
class ScanConfig:
    scan_root: Path
    pth_max_depth: int = 4
    pth_max_hits: int = 50
    venv_walk_depth: int = 8
    skip_docker: bool = False
    skip_processes: bool = False
    verbose: bool = False
    cache_max_files: int = 100_000
    cache_max_hits: int = 200
    python_info_timeout_seconds: float = 5.0
    docker_timeout_seconds: float = 15.0


def _severity(
    installed: list[dict],
    pth: list[dict],
    cache_hits: list[dict],
    net_danger: bool,
    docker_danger: bool,
    hosts_ioc: bool,
) -> str:
    if any(x.get("compromised") for x in installed):
        return "danger"
    if pth:
        return "danger"
    if cache_hits:
        return "danger"
    if net_danger:
        return "danger"
    if docker_danger:
        return "danger"
    if hosts_ioc:
        return "danger"
    if installed:
        return "warning"
    return "clean"


def run_scan(config: ScanConfig) -> tuple[dict[str, Any], int]:
    def _log(msg: str) -> None:
        if config.verbose:
            print(msg, file=sys.stderr)

    root = config.scan_root.expanduser().resolve()
    scan_roots = [root] if root.is_dir() else []

    phases: dict[str, Any] = {}

    _log("[1/8] Discover Python environments...")
    envs = discover_environments(
        scan_roots=scan_roots,
        venv_walk_depth=config.venv_walk_depth,
        verbose=config.verbose,
        python_info_timeout_seconds=config.python_info_timeout_seconds,
    )
    phases["python_environments"] = {"count": len(envs), "environments": envs}

    _log("[2/8] Scan installed litellm versions...")
    installed = scan_installed_in_environments(envs)
    phases["installed_litellm"] = installed
    phases["indirect_installed_dependency"] = scan_indirect_dependency_in_environments(envs)

    _log("[3/8] Scan dependency manifests under scan_root...")
    dep_hits: list[dict] = []
    if root.is_dir():
        dep_hits = scan_dependency_files(root)
    phases["dependency_files"] = dep_hits

    _log("[4/8] Scan pip/uv/Poetry/Hatch caches...")
    cache_hits = scan_package_caches(
        max_files=config.cache_max_files,
        max_hits=config.cache_max_hits,
    )
    phases["pip_uv_cache"] = cache_hits

    site_dirs: list[str] = []
    for e in envs:
        site_dirs.extend(e.get("site_packages") or [])
    _log("[5/8] Scan litellm_init.pth IOC...")
    pth_fast = find_pth_in_site_packages(site_dirs, verbose=config.verbose)
    pth_slow: list[dict] = []
    pth_system = find_pth_in_system_locations(
        max_hits=config.pth_max_hits,
        verbose=config.verbose,
    )
    if config.pth_max_depth > 0 and root.is_dir():
        pth_slow = find_litellm_init_pth(
            root, max_depth=config.pth_max_depth, max_hits=config.pth_max_hits, verbose=config.verbose
        )
    seen_pth: set[str] = set()
    pth_hits: list[dict] = []
    for row in pth_fast + pth_slow + pth_system:
        key = row.get("path", "")
        if key in seen_pth:
            continue
        seen_pth.add(key)
        pth_hits.append(row)
    phases["pth_ioc"] = pth_hits

    net_danger = False
    if not config.skip_processes:
        _log("[6/9] Scan processes / network...")
        proc = scan_processes_and_network()
        phases["processes_and_network"] = proc
        if proc.get("status") == "ok":
            for c in proc.get("connections") or []:
                r = c.get("remote")
                if r and remote_endpoint_matches_malicious_ioc(r):
                    net_danger = True
    else:
        phases["processes_and_network"] = {"status": "skipped", "reason": "--no-processes"}

    _log("[7/8] Scan hosts file IOC...")
    hosts = scan_hosts_file_for_ioc()
    phases["hosts_ioc"] = hosts
    hosts_ioc = bool(hosts.get("matched_lines") or [])

    docker_danger = False
    if not config.skip_docker:
        _log("[8/8] Scan Docker image tags...")
        docker = scan_docker_images(timeout_seconds=config.docker_timeout_seconds)
        phases["docker"] = docker
        docker_danger = bool(docker.get("compromised_images"))
    else:
        phases["docker"] = {"status": "skipped", "reason": "--no-docker"}

    litellm_in_dep = bool(dep_hits)

    worst = _severity(installed, pth_hits, cache_hits, net_danger, docker_danger, hosts_ioc)
    if worst == "clean" and litellm_in_dep:
        worst = "warning"

    exit_code = 0
    if worst == "warning":
        exit_code = 1
    elif worst == "danger":
        exit_code = 2

    summary = {
        "product": PRODUCT_NAME,
        "version": __version__,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "scan_root": str(root),
        "compromised_versions": sorted(COMPROMISED_VERSIONS),
        "malicious_domain": MALICIOUS_DOMAIN,
        "summary_level": worst,
        "has_litellm_in_dependency_files": litellm_in_dep,
    }

    report: dict[str, Any] = {"summary": summary, "phases": phases}
    return report, exit_code


def write_report(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"litellm-supply-chain-audit-{ts}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def report_to_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    s = report.get("summary") or {}
    lines.append("litellm-supply-chain-audit")
    lines.append("--------------------------")
    lines.append("March 2026 PyPI incident — known-bad: 1.82.7, 1.82.8")
    lines.append("")
    lines.append(f"Result: {s.get('summary_level', '?').upper()}")
    lines.append(f"Scan root: {s.get('scan_root', '')}")
    lines.append("")

    phases = report.get("phases") or {}
    envs = phases.get("python_environments") or {}
    lines.append(f"[1/7] Python environments: {envs.get('count', 0)}")

    inst = phases.get("installed_litellm") or []
    lines.append(f"[2/7] Installed litellm: {len(inst)}")
    for row in inst[:20]:
        lines.append(
            f"  - {row.get('litellm_version')} @ {row.get('site_packages')}"
            + ("  [BAD VERSION]" if row.get("compromised") else "")
        )

    deps = phases.get("dependency_files") or []
    lines.append(f"[3/7] Dependency files referencing litellm: {len(deps)}")
    for row in deps[:15]:
        raw = row.get("path") or row.get("relative") or ""
        try:
            disp = str(Path(raw).resolve())
        except OSError:
            disp = str(raw)
        disp_one = " ".join(disp.splitlines())
        lines.append(f"  - {disp_one}")

    indirect = phases.get("indirect_installed_dependency") or []
    lines.append(f"      installed packages requiring litellm: {len(indirect)}")
    for row in indirect[:15]:
        lines.append(f"        - {row.get('package')} ({row.get('python')})")

    cache = phases.get("pip_uv_cache") or []
    lines.append(f"[4/7] pip/uv/Poetry/Hatch cache (suspicious filenames): {len(cache)}")

    pth = phases.get("pth_ioc") or []
    lines.append(f"[5/7] litellm_init.pth IOC: {len(pth)}")
    for row in pth[:10]:
        lines.append(
            f"  - {row.get('path')} suspicious_domain={row.get('suspicious_domain_present')}"
        )

    proc = phases.get("processes_and_network") or {}
    lines.append(f"[6/7] Processes / network: {proc.get('status', '?')}")
    if proc.get("status") == "skipped" and proc.get("reason"):
        pr = " ".join(str(proc["reason"]).split())
        if len(pr) > 220:
            pr = pr[:217] + "..."
        lines.append(f"      note: {pr}")

    hosts = phases.get("hosts_ioc") or {}
    if hosts.get("status") == "ok":
        host_hits = hosts.get("matched_lines") or []
        lines.append(f"      hosts IOC lines: {len(host_hits)}")
        for ln in host_hits[:5]:
            lines.append(f"        - {ln}")

    dock = phases.get("docker") or {}
    lines.append(f"[7/7] Docker: {dock.get('status', '?')}")
    if dock.get("status") in ("error", "skipped") and dock.get("reason"):
        r = " ".join(str(dock["reason"]).split())
        if len(r) > 220:
            r = r[:217] + "..."
        lines.append(f"      note: {r}")
    if dock.get("matching_images"):
        for im in (dock.get("matching_images") or [])[:10]:
            lines.append(f"  - {im}")
    if dock.get("compromised_images"):
        lines.append("      compromised version tags:")
        for im in (dock.get("compromised_images") or [])[:10]:
            lines.append(f"        - {im}")

    lines.append("")
    level = s.get("summary_level", "clean")
    if level == "clean":
        lines.append("No known-bad versions or high-confidence IOCs detected in this run.")
    elif level == "warning":
        lines.append("Warning: litellm is present or referenced — verify versions and provenance.")
    else:
        lines.append(
            "Danger: known-bad version, IOC, cache artifact, or suspicious network signal."
        )

    return "\n".join(lines) + "\n"
