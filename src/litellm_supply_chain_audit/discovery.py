"""Discover Python executables and their site-packages paths."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

_SUPPORTED_MINOR_VERSIONS: tuple[str, ...] = ("10", "11", "12", "13", "14")

_SITE_INFO_SCRIPT = r"""import json, site, sys
paths = []
try:
    paths.extend(site.getsitepackages())
except Exception:
    pass
try:
    u = site.getusersitepackages()
    if u:
        paths.append(u)
except Exception:
    pass
print(json.dumps({"executable": sys.executable, "site_packages": paths}))
"""


def _safe_run_python(python: Path, timeout: float = 30.0) -> dict | None:
    try:
        proc = subprocess.run(
            [str(python), "-c", _SITE_INFO_SCRIPT],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
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
        for minor in _SUPPORTED_MINOR_VERSIONS:
            name = f"Python3{minor}"
            p = Path(pf) / name / "python.exe"
            if p.is_file():
                found.append(p)
    pf86 = os.environ.get("ProgramFiles(x86)", "")
    if pf86:
        for minor in _SUPPORTED_MINOR_VERSIONS:
            name = f"Python3{minor}"
            p = Path(pf86) / name / "python.exe"
            if p.is_file():
                found.append(p)
    for name in ("miniconda3", "anaconda3", "mambaforge", "miniforge3"):
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
    for conda in (home / "miniconda3", home / "anaconda3", home / "mambaforge"):
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
    """Common Homebrew / Linux locations (macOS arm64/x86_64 and typical distros)."""
    candidates: list[str] = [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
        "/usr/bin/python",
    ]
    for minor in _SUPPORTED_MINOR_VERSIONS:
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


def collect_python_candidates(extra_roots: list[Path] | None = None) -> list[Path]:
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
            candidates.extend(_venv_pythons_under(root))
            try:
                for child in root.iterdir():
                    if child.is_dir():
                        candidates.extend(_venv_pythons_under(child))
            except OSError:
                pass

    return _dedupe_paths(candidates)


def _venv_pythons_under(root: Path) -> list[Path]:
    """Typical project venv layouts only (avoids expensive full-tree rglob)."""
    found: list[Path] = []
    for name in (".venv", "venv", "env", ".env", ".virtualenv", ".conda"):
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


def discover_environments(scan_roots: list[Path] | None = None) -> list[dict]:
    """
    Return list of { "python": str, "site_packages": [str, ...] } for each working interpreter.
    """
    roots = [r.resolve() for r in (scan_roots or []) if r.is_dir()]
    candidates = collect_python_candidates(extra_roots=roots)
    envs: list[dict] = []
    seen_sp: set[str] = set()

    for py in candidates:
        data = _safe_run_python(py)
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
