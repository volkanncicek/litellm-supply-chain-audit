"""Discover Python executables and their site-packages paths."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .constants import (
    CONDA_HOME_DIR_NAMES,
    PROJECT_VENV_DIR_NAMES,
    SUPPORTED_PYTHON_MINOR_VERSIONS,
    VENV_WALK_SKIP_DIRS,
)

_SITE_INFO_SCRIPT = r"""import json, sysconfig, sys

paths = []
for k in ("purelib", "platlib"):
    p = sysconfig.get_path(k)
    if p:
        paths.append(p)

# "user" scheme may not exist in some distributions; ignore failures.
try:
    for k in ("purelib", "platlib"):
        p = sysconfig.get_path(k, scheme="user")
        if p:
            paths.append(p)
except Exception:
    pass

# Don't import `site` (avoid executing `.pth`).
print(json.dumps({"executable": sys.executable, "site_packages": paths}))
"""


def _safe_run_python(
    python: Path,
    timeout: float = 5.0,
    verbose: bool = False,
) -> dict | None:
    try:
        proc = subprocess.run(
            # -S disables importing `site` at startup; this avoids executing `.pth` files.
            [str(python), "-S", "-c", _SITE_INFO_SCRIPT],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        if verbose:
            print(f"[discovery] Failed to query python: {python}", file=sys.stderr)
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        if verbose:
            print(f"[discovery] Python returned no site info: {python}", file=sys.stderr)
        return None
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except json.JSONDecodeError:
        return None


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        key = str(resolved).casefold() if os.name == "nt" else str(resolved)
        if key not in seen:
            seen.add(key)
            out.append(resolved)
    return out


def _windows_python_candidates() -> list[Path]:
    found: list[Path] = []
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        base = Path(local) / "Programs" / "Python"
        if base.is_dir():
            found.extend(base.rglob("python.exe"))
    pf = os.environ.get("ProgramFiles", "")
    if pf:
        for minor in SUPPORTED_PYTHON_MINOR_VERSIONS:
            name = f"Python3{minor}"
            p = Path(pf) / name / "python.exe"
            if p.is_file():
                found.append(p)
    pf86 = os.environ.get("ProgramFiles(x86)", "")
    if pf86:
        for minor in SUPPORTED_PYTHON_MINOR_VERSIONS:
            name = f"Python3{minor}"
            p = Path(pf86) / name / "python.exe"
            if p.is_file():
                found.append(p)
    for name in CONDA_HOME_DIR_NAMES:
        home = Path.home() / name / "python.exe"
        if home.is_file():
            found.append(home)
    pipx = os.environ.get("PIPX_HOME")
    if pipx:
        p = Path(pipx) / "venvs"
        if p.is_dir():
            found.extend(p.rglob("python.exe"))
    else:
        default_pipx = Path.home() / "pipx" / "venvs"
        if default_pipx.is_dir():
            found.extend(default_pipx.rglob("python.exe"))
    return found


def _unix_python_candidates() -> list[Path]:
    found: list[Path] = []
    home = Path.home()
    pyenv_root = os.environ.get("PYENV_ROOT", str(home / ".pyenv"))
    versions = Path(pyenv_root) / "versions"
    if versions.is_dir():
        for d in versions.iterdir():
            if d.is_dir():
                for name in ("bin/python", "bin/python3"):
                    p = d / name
                    if p.is_file() and os.access(p, os.X_OK):
                        found.append(p)
    for name in CONDA_HOME_DIR_NAMES:
        conda = home / name
        p = conda / "bin" / "python"
        if p.is_file():
            found.append(p)
    workon_home = Path(os.environ.get("WORKON_HOME", str(home / ".virtualenvs")))
    if workon_home.is_dir():
        for venv in workon_home.iterdir():
            p = venv / "bin" / "python"
            if p.is_file() and os.access(p, os.X_OK):
                found.append(p)
    pipx_home = Path(os.environ.get("PIPX_HOME", str(home / ".local" / "pipx")))
    pipx_venvs = pipx_home / "venvs"
    if pipx_venvs.is_dir():
        for venv in pipx_venvs.iterdir():
            p = venv / "bin" / "python"
            if p.is_file() and os.access(p, os.X_OK):
                found.append(p)
    uv_pythons = home / ".local" / "share" / "uv" / "python"
    if uv_pythons.is_dir():
        found.extend(uv_pythons.rglob("python3"))
        found.extend(uv_pythons.rglob("python"))
    found.extend(_posix_std_interpreters())
    return found


def _posix_std_interpreters() -> list[Path]:
    """Common system locations."""
    candidates: list[str] = [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
        "/usr/bin/python",
    ]
    for minor in SUPPORTED_PYTHON_MINOR_VERSIONS:
        candidates.append(f"/opt/homebrew/bin/python3.{minor}")
        candidates.append(f"/usr/local/opt/python@3.{minor}/bin/python3")
    out: list[Path] = []
    for raw in candidates:
        p = Path(raw)
        try:
            if p.is_file() and os.access(p, os.X_OK):
                out.append(p)
        except OSError:
            continue
    return out


def _py_launcher_list() -> list[Path]:
    py_exe = shutil.which("py")
    if not py_exe or os.name != "nt":
        return []
    try:
        proc = subprocess.run(
            [py_exe, "-0p"],
            capture_output=True,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    out: list[Path] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Installed"):
            continue
        # e.g. "-3.12-64\tC:\Path\python.exe" or "-V:3.12\t..."
        parts = line.split("\t", 1)
        path_str = parts[-1].strip().strip('"')
        if path_str.lower().endswith("python.exe") or path_str.lower().endswith("python"):
            p = Path(path_str)
            if p.is_file():
                out.append(p)
    return out


def _which_pythons() -> list[Path]:
    out: list[Path] = []
    for name in ("python", "python3", "pythonw"):
        w = shutil.which(name)
        if w:
            out.append(Path(w))
    return out


def _venv_pythons_shallow(root: Path) -> list[Path]:
    """Common project venv layouts."""
    found: list[Path] = []
    for name in PROJECT_VENV_DIR_NAMES:
        if os.name == "nt":
            p = root / name / "Scripts" / "python.exe"
            if p.is_file():
                found.append(p)
        else:
            p3 = root / name / "bin" / "python3"
            p = root / name / "bin" / "python"
            if p3.is_file():
                found.append(p3)
            elif p.is_file():
                found.append(p)
    return found


def _find_venv_pythons_by_pyvenv_cfg(
    root: Path,
    max_depth: int,
    max_hits: int = 3000,
) -> list[Path]:
    """
    Find venv interpreters by locating `pyvenv.cfg` under `root` up to `max_depth`.
    This catches venvs regardless of directory name.
    """
    if max_depth <= 0:
        return []
    root = root.resolve()
    found: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        cur = Path(dirpath)
        try:
            rel = cur.relative_to(root)
            depth = len(rel.parts)
        except ValueError:
            depth = 0

        if depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in VENV_WALK_SKIP_DIRS]

        if "pyvenv.cfg" not in filenames:
            continue

        if os.name == "nt":
            py = cur / "Scripts" / "python.exe"
        else:
            py = cur / "bin" / "python3"
            if not py.is_file():
                py = cur / "bin" / "python"

        if py.is_file():
            found.append(py)
            if len(found) >= max_hits:
                return found

    return found


def collect_python_candidates(
    extra_roots: list[Path] | None = None,
    venv_walk_depth: int = 8,
) -> list[Path]:
    """Collect likely Python executables (heuristic, not exhaustive)."""
    candidates: list[Path] = [Path(sys.executable)]
    candidates.extend(_which_pythons())
    if os.name == "nt":
        candidates.extend(_windows_python_candidates())
        candidates.extend(_py_launcher_list())
    else:
        candidates.extend(_unix_python_candidates())

    if extra_roots:
        for root in extra_roots:
            candidates.extend(_venv_pythons_shallow(root))
            candidates.extend(_find_venv_pythons_by_pyvenv_cfg(root, max_depth=venv_walk_depth))

    return _dedupe_paths(candidates)


def discover_environments(
    scan_roots: list[Path] | None = None,
    venv_walk_depth: int = 8,
    verbose: bool = False,
    python_info_timeout_seconds: float = 5.0,
) -> list[dict]:
    """
    Return list of { "python": str, "site_packages": [str, ...] } for each working interpreter.
    """
    roots = [r.resolve() for r in (scan_roots or []) if r.is_dir()]
    candidates = collect_python_candidates(extra_roots=roots, venv_walk_depth=venv_walk_depth)
    envs: list[dict] = []
    seen_sp: set[str] = set()

    for py in candidates:
        data = _safe_run_python(py, timeout=python_info_timeout_seconds, verbose=verbose)
        if not data:
            continue
        exe = data.get("executable")
        sps = data.get("site_packages") or []
        if not exe:
            continue
        # Dedupe by tuple of site-packages
        key = "|".join(sorted(str(x) for x in sps))
        if key in seen_sp:
            continue
        seen_sp.add(key)
        envs.append({"python": exe, "site_packages": [str(x) for x in sps]})

    return envs
