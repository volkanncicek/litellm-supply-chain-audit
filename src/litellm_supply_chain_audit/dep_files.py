"""Scan project manifests for litellm references."""

import os
import re
import tomllib
from pathlib import Path

from .constants import DEPENDENCY_MANIFEST_FILE_NAMES, FS_WALK_SKIP_DIRS_COMMON, PACKAGE_NAME

# PEP 508 name at start of requirement line
_RE_REQ = re.compile(rf"(?i)^{re.escape(PACKAGE_NAME)}([\s\[<>=!~,;]|$)")


def _req_line_mentions_litellm(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith("#"):
        return False
    return bool(_RE_REQ.search(s))


def _pyproject_declares_litellm(path: Path) -> bool:
    """True only if a dependency table lists the `litellm` package (not name/description prose)."""
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError:
        return False

    project = data.get("project") or {}
    for dep in project.get("dependencies") or []:
        if isinstance(dep, str) and _req_line_mentions_litellm(dep):
            return True

    opt = project.get("optional-dependencies") or {}
    for group in opt.values():
        if not isinstance(group, list):
            continue
        for dep in group:
            if isinstance(dep, str) and _req_line_mentions_litellm(dep):
                return True

    groups = data.get("dependency-groups") or {}
    for group in groups.values():
        if not isinstance(group, list):
            continue
        for dep in group:
            if isinstance(dep, str) and _req_line_mentions_litellm(dep):
                return True

    poetry = (data.get("tool") or {}).get("poetry") or {}
    pdeps = poetry.get("dependencies")
    if isinstance(pdeps, dict) and PACKAGE_NAME in pdeps:
        return True

    uv = (data.get("tool") or {}).get("uv") or {}
    for key in ("dev-dependencies", "override-dependencies"):
        block = uv.get(key)
        if isinstance(block, list):
            for dep in block:
                if isinstance(dep, str) and _req_line_mentions_litellm(dep):
                    return True

    pipenv = data.get("pipenv") or {}
    packages = pipenv.get("packages")
    if isinstance(packages, dict) and PACKAGE_NAME in packages:
        return True

    return False


def _generic_file_mentions(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        if _req_line_mentions_litellm(line):
            return True
    return False


def scan_dependency_files(root: Path, max_files: int = 5000) -> list[dict]:
    """
    Walk `root` for common dependency files and report paths that reference litellm.
    """
    findings: list[dict] = []
    count = 0

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in FS_WALK_SKIP_DIRS_COMMON]
        for name in filenames:
            if count >= max_files:
                return findings

            is_candidate = (
                name == "pyproject.toml"
                or name in DEPENDENCY_MANIFEST_FILE_NAMES
                or (name.startswith("requirements") and name.endswith(".txt"))
                or (
                    name.startswith("conda-env")
                    and (name.endswith(".yml") or name.endswith(".yaml"))
                )
            )
            if not is_candidate:
                continue

            count += 1
            path = Path(dirpath) / name
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = str(path)

            if name == "pyproject.toml":
                if _pyproject_declares_litellm(path):
                    findings.append({"path": str(path), "kind": "pyproject.toml", "relative": rel})
                continue

            if _generic_file_mentions(path):
                findings.append({"path": str(path), "kind": name, "relative": rel})

    seen: set[str] = set()
    unique: list[dict] = []
    for row in findings:
        try:
            key = str(Path(row["path"]).resolve())
        except OSError:
            key = row["path"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique
