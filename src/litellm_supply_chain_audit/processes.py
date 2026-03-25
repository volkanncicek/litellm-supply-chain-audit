"""Process and network IOC checks via psutil."""

from typing import Any

import psutil

from .constants import PACKAGE_NAME, remote_host_matches_malicious_ioc


def scan_processes_and_network() -> dict[str, Any]:
    proc_hits: list[dict] = []
    for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            info = p.info
            cmd = info.get("cmdline") or []
            text = " ".join(cmd).lower()
            if PACKAGE_NAME in text:
                proc_hits.append({"pid": info.get("pid"), "cmdline_sample": cmd[:20]})
        except (psutil.Error, TypeError):
            continue

    net_hits: list[dict] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, PermissionError):
        conns = []
    for c in conns:
        try:
            raddr = getattr(c, "raddr", None)
            if raddr and len(raddr) >= 1:
                host = raddr[0]
                if remote_host_matches_malicious_ioc(host):
                    net_hits.append(
                        {
                            "pid": c.pid,
                            "local": getattr(c, "laddr", None),
                            "remote": raddr,
                            "status": getattr(c, "status", None),
                        }
                    )
        except (psutil.Error, TypeError):
            continue

    return {
        "status": "ok",
        "processes_mentioning_litellm": proc_hits[:50],
        "connections": net_hits[:50],
    }
