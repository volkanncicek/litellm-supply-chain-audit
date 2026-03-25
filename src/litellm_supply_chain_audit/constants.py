"""
Project-wide constants.
"""

PRODUCT_NAME: str = "litellm-supply-chain-audit"

COMPROMISED_VERSIONS: frozenset[str] = frozenset({"1.82.7", "1.82.8"})
MALICIOUS_DOMAIN: str = "models.litellm.cloud"
PTH_IOC_NAME: str = "litellm_init.pth"
PACKAGE_NAME: str = "litellm"

FS_WALK_SKIP_DIRS_COMMON: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".tox",
        "dist",
        "build",
    }
)

DEPENDENCY_MANIFEST_FILE_NAMES: frozenset[str] = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements_dev.txt",
        "constraints.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "setup.py",
        "setup.cfg",
        "environment.yml",
        "environment.yaml",
    }
)

SUPPORTED_PYTHON_MINOR_VERSIONS: tuple[str, ...] = ("10", "11", "12", "13", "14")

PROJECT_VENV_DIR_NAMES: tuple[str, ...] = (
    ".venv",
    "venv",
    "env",
    ".env",
    ".virtualenv",
    ".conda",
)

VENV_WALK_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
        "dist",
        "build",
    }
)

CONDA_HOME_DIR_NAMES: tuple[str, ...] = ("miniconda3", "anaconda3", "mambaforge", "miniforge3")


def remote_host_matches_malicious_ioc(host: object) -> bool:
    """True for the known IOC host (exact or DNS suffix), not other *.litellm.cloud names."""
    h = str(host).strip().lower().rstrip(".")
    if not h:
        return False
    return h == MALICIOUS_DOMAIN or h.endswith("." + MALICIOUS_DOMAIN)


def remote_endpoint_matches_malicious_ioc(remote: object) -> bool:
    """psutil-style remote address: tuple (host, port) or similar."""
    if remote is None:
        return False
    if isinstance(remote, (tuple, list)) and len(remote) >= 1:
        return remote_host_matches_malicious_ioc(remote[0])
    return remote_host_matches_malicious_ioc(remote)
