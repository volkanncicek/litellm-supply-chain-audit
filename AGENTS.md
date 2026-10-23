# AGENTS.md

Coding agent guide for **litellm-supply-chain-audit** — a cross-platform Python CLI utility that audits a local environment for the **March 2026 litellm supply-chain incident** (IOCs + known-bad versions).

Open-source MIT-licensed tool, installed from GitHub (clone or `uvx --from git+...`); it is not on PyPI. The README is the user-facing reference and the single source for install, usage, the CLI flags, the scan phases, the exit codes, the report shape, limitations and incident triage — read it rather than restating it here.

---

## Project Overview

- **Build:** `hatchling` (packages = `src/litellm_supply_chain_audit`); Python version from `requires-python` in `pyproject.toml`
- **Entry point:** `litellm-supply-chain-audit` (`src/litellm_supply_chain_audit/cli.py`); `scanner.py` orchestrates the phases and computes the exit code
- **Dependencies:** `psutil` only (process/network phase)
- **Optional:** Docker CLI for the Docker phase; without it the phase is reported as skipped. The skip is intentional — the tool must still run on a developer machine without Docker, so don't promote it to an error
- **Known-bad versions** live in `COMPROMISED_VERSIONS` in `constants.py`; that is the single place to change them

---

## Commands

```bash
uv run litellm-supply-chain-audit --help
uv run litellm-supply-chain-audit . --no-report-file --no-docker   # quick run from source
uvx ruff check .                                                  # lint (config in pyproject.toml; ruff is not a project dependency)
```

Tests: `uv run pytest` (fixture site-packages and caches; never installs litellm). CI runs lint and tests on Linux, Windows and macOS.

`--pth-max-depth` defaults conservatively to avoid hammering huge home directories; deep searches pass it explicitly.

Cross-platform paths matter (Windows, macOS, Linux): don't hardcode separators or assume case-sensitivity.

---

## Critical Rules

1. **Don't widen scope beyond known IOCs.** This is a targeted incident-response tool, not a general malware scanner. Adding heuristic "looks suspicious" checks is a feature creep that produces false positives and erodes trust in the `0` exit code.
2. **Keep `psutil` the only required dependency.** The tool needs to run on bare Python on an unknown machine — any dep we add is a dep someone has to install under stress during incident response. Keep `pyproject.toml` lean.
3. **JSON output and exit codes are the machine contract** (see README "Report shape" and "Exit codes"). Don't change either without bumping a version note; downstream automation parses them.
4. **Don't hardcode a "safe" litellm version into scan logic.** The maintainer-approved pin evolves; defer to [BerriAI/litellm#24512](https://github.com/BerriAI/litellm/issues/24512).
5. **Don't print or log credentials/secrets found incidentally.** If a phase surfaces an env file or token, redact in output.
