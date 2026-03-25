"""List local Docker images whose names/tags suggest litellm."""

import re
import subprocess
from typing import Any

from .constants import COMPROMISED_VERSIONS


def _docker_daemon_unreachable(stderr: str) -> bool:
    """True when failure is almost certainly 'Docker not running' vs a real CLI misuse."""
    s = stderr.lower()
    needles = (
        "failed to connect",
        "cannot connect to the docker daemon",
        "error during connect",
        "connection refused",
        "the system cannot find the file specified",
        "dockerdesktoplinuxengine",
        "npipe://",
        "pipe/docker",
        "is the docker daemon running",
    )
    return any(n in s for n in needles)


def scan_docker_images(timeout_seconds: float = 15.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return {"status": "skipped", "reason": "docker CLI not found in PATH"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "reason": f"docker image ls timed out after {timeout_seconds}s"}

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        err_one_line = re.sub(r"\s+", " ", err)
        if _docker_daemon_unreachable(err):
            return {
                "status": "skipped",
                "reason": "Docker daemon not reachable (start Docker Desktop or use --no-docker).",
                "detail": err_one_line[:4000],
            }
        return {
            "status": "error",
            "reason": err_one_line or "docker image ls failed",
        }

    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    hits: list[str] = []
    for ln in lines:
        low = ln.lower()
        # Avoid dangling/noise entries like "<none>:<none>".
        if low == "<none>:<none>":
            continue
        if "litellm" in low:
            hits.append(ln)
    compromised: list[str] = []
    for image in hits:
        low = image.lower()
        if any(v in low for v in COMPROMISED_VERSIONS):
            compromised.append(image)
    return {
        "status": "ok",
        "matching_images": hits,
        "compromised_images": compromised,
    }
