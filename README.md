# litellm-supply-chain-audit

**What this is:** A standalone **Python 3.11+** CLI that audits **your machine** for signs of the **March 24, 2026** [litellm PyPI supply-chain incident](https://github.com/BerriAI/litellm/issues/24512): known-bad versions **`1.82.7` / `1.82.8`**, the **`litellm_init.pth`** file, **`models.litellm.cloud`** in network visibility, dependency manifests, and caches. It runs **natively on Windows, macOS, and Linux** (no WSL required on Windows).

**What this is not:** It is **not** published by BerriAI and **not** a fork of litellm. It is an independent security utility implemented in **Python + stdlib + psutil**, focused on cross-platform behavior with native Windows support.

**Distribution:** Install [from this repository](#install) only—**not on PyPI** (clone or VCS URL). Repository: [github.com/volkanncicek/litellm-supply-chain-audit](https://github.com/volkanncicek/litellm-supply-chain-audit). License: [MIT](LICENSE).

---

## Incident (short)

| | |
|--|--|
| **Bad versions** | `litellm==1.82.7`, `litellm==1.82.8` |
| **Mechanism** | Malicious `litellm_init.pth` under `site-packages` (runs at interpreter startup; **import not required**) |
| **Reported IOC** | Exfiltration tied to **`models.litellm.cloud`** (see upstream issues) |

### Upstream issues (why each matters)

| Issue | Why you should read it |
|---|---|
| [#24512](https://github.com/BerriAI/litellm/issues/24512) | **Primary incident thread**: maintainer updates, community forensics, and remediation guidance (canonical source). |
| [#24515](https://github.com/BerriAI/litellm/issues/24515) | **Malicious `litellm_init.pth` analysis**: payload behavior and IOC details useful for validation. |
| [#24517](https://github.com/BerriAI/litellm/issues/24517) | **Package registry status**: quarantine and takedown context for ecosystem impact. |
| [#24518](https://github.com/BerriAI/litellm/issues/24518) | **Timeline and status tracking**: sequence of events for incident reconstruction. |
| [#24542](https://github.com/BerriAI/litellm/issues/24542) | **Hardening follow-up**: Trusted Publishers/OIDC migration and prevention measures. |

---

## What the scan does (7 phases)

| # | Phase | This tool |
|---|--------|-----------|
| 1 | Environments | Heuristic discovery: `PATH` / Windows `py`, common prefixes, pyenv/conda/homebrew-style paths, explicit Python `3.10`–`3.14` install paths (including `Program Files` and `Program Files (x86)`), and `.venv` / `venv` / `env` / `.env` / `.virtualenv` / `.conda` under the scan root (not every niche layout). Discovery runs Python with `-S` (no `site` import) to avoid executing any `.pth` side effects. |
| 2 | Installed packages | Reads `litellm-*.dist-info/METADATA` and `litellm-*.egg-info/PKG-INFO` only—**no `import litellm`**. Flags **1.82.7 / 1.82.8** and also reports any installed package metadata that declares `Requires-Dist: litellm`. |
| 3 | Manifests | `pyproject.toml` dependency tables; line scan of `requirements*.txt`, Pipfile, lockfiles, `setup.py` / `setup.cfg`, etc. |
| 4 | pip / uv cache | Known cache locations; filenames suggesting **1.82.7 / 1.82.8** artifacts. |
| 5 | `.pth` IOC | Fast: `litellm_init.pth` beside discovered `site-packages`; also checks common system Python locations. For deeper scanning under `scan_root`, set **`--pth-max-depth > 0`**. |
| 6 | Processes / network | **psutil**: command lines mentioning `litellm`; connections to the known malicious host when the OS exposes them; plus `hosts` file IOC line check for `models.litellm.cloud`. |
| 7 | Docker | **`docker image ls`**—name/tag match only; no layer inspection. Detects `litellm` tags containing **1.82.7 / 1.82.8** as danger. Skipped if the daemon is down; use **`--no-docker`** to skip the CLI call. |

---

## Limitations (read before trusting “clean”)

- **Discovery is heuristic**—not every Python on the disk is guaranteed to appear.
- **Transitive dependencies** from manifests are **not** fully resolved; phase 2 is “what is installed,” not “what pip would resolve.”
- **Manifest hit** = “litellm referenced,” not automatically a bad version (warnings use [exit codes](#exit-codes)).
- **Network** listing may be empty without permissions; **Docker** still matches image **names/tags only** (not image layers); deeper `.pth` scanning is controlled by **`--pth-max-depth`**.

---

## Platform support

| Platform | Notes |
|----------|--------|
| **Windows** | Native paths, `py` launcher, `%LOCALAPPDATA%` installs. |
| **macOS / Linux** | Standard layouts and user cache paths. |

**psutil** is required (phase 6). **Docker CLI** is optional (phase 7).

---

## Prerequisites

- **Python ≥ 3.11**
- **[uv](https://github.com/astral-sh/uv)** (recommended for install) or **pip**
- **Docker CLI** (optional)

---

## Install

**Recommended — uv**

```bash
git clone https://github.com/volkanncicek/litellm-supply-chain-audit.git
cd litellm-supply-chain-audit
uv sync
uv run litellm-supply-chain-audit --help
```

**Alternative — pip**

```bash
git clone https://github.com/volkanncicek/litellm-supply-chain-audit.git
cd litellm-supply-chain-audit
python -m pip install .
# editable: python -m pip install -e .
```

After install: `litellm-supply-chain-audit` on `PATH`, or `python -m litellm_supply_chain_audit`.

---

## Usage

```bash
# Default scan root: home directory
litellm-supply-chain-audit

# Scan a tree
litellm-supply-chain-audit /path/to/projects

# JSON only
litellm-supply-chain-audit --json-only

# Optional: deeper recursive search for litellm_init.pth under scan_root
litellm-supply-chain-audit /path/to/root --pth-max-depth 8

litellm-supply-chain-audit --no-processes --no-docker
```

### CLI reference

| Option | Description |
|--------|-------------|
| `scan_root` | Optional; default: user home |
| `--venv-walk-depth N` | Depth-limited venv discovery under `scan_root` via `pyvenv.cfg` (default **8**; `0` disables) |
| `--pth-max-depth N` | Recursive `litellm_init.pth` search depth under `scan_root` (default **4**; `0` disables) |
| `--no-docker` | Skip Docker |
| `--no-processes` | Skip process/socket phase |
| `--json-only` | Print JSON only |
| `--no-report-file` | Do not write JSON file |
| `--report-dir DIR` | Report directory (default: scan root) |

### Exit codes

| Code | Meaning |
|------|--------|
| `0` | No warning/danger-level findings |
| `1` | Warning (e.g. litellm present but not a flagged version, or referenced in manifests) |
| `2` | Danger (bad versions, IOC, suspicious cache, matching network signal) |
| `3` | Execution error |

---

## Example output (text)

```
litellm-supply-chain-audit
--------------------------
March 2026 PyPI incident — known-bad: 1.82.7, 1.82.8

Result: CLEAN
Scan root: /home/user

[1/7] Python environments: 3
[2/7] Installed litellm: 0
...
No known-bad versions or high-confidence IOCs detected in this run.
```

JSON report: **`litellm-supply-chain-audit-<timestamp>.json`** in the scan root (or `--report-dir`), unless `--no-report-file`.

---

## Report shape

```json
{
  "summary": {
    "product": "litellm-supply-chain-audit",
    "version": "...",
    "timestamp_utc": "...",
    "scan_root": "...",
    "compromised_versions": ["1.82.7", "1.82.8"],
    "malicious_domain": "models.litellm.cloud",
    "summary_level": "clean | warning | danger",
    "has_litellm_in_dependency_files": false,
    "report_path": "..."
  },
  "phases": {
    "python_environments": {},
    "installed_litellm": [],
    "indirect_installed_dependency": [],
    "dependency_files": [],
    "pip_uv_cache": [],
    "pth_ioc": [],
    "processes_and_network": {},
    "hosts_ioc": {},
    "docker": {}
  }
}
```

---

## If you find danger or IOCs

1. **Disconnect** if you suspect active exfiltration.
2. **Rotate** credentials that may have lived on affected machines.
3. **Pin** to a maintainer-approved safe version—historically **`litellm==1.82.6`** was cited; **confirm on [#24512](https://github.com/BerriAI/litellm/issues/24512)**.
4. **Remove** bad installs and **`litellm_init.pth`** under `site-packages` and elsewhere.
5. **Audit** logs for **`models.litellm.cloud`**.
6. **Follow** upstream guidance: track [#24512](https://github.com/BerriAI/litellm/issues/24512) for live remediation updates and [#24542](https://github.com/BerriAI/litellm/issues/24542) for hardening actions.

---

## Development

```bash
uv sync
uv run python -m compileall -q src
uv run litellm-supply-chain-audit . --no-report-file --no-docker
```

Or with pip: `python -m pip install -e .` then the same commands without `uv run`.

**Quick check:** `uv run litellm-supply-chain-audit --help`

---

## Tech stack

- Python 3.11+, standard library
- **psutil** (processes/sockets)
- Optional **Docker CLI** subprocess for local image names
