import json
from pathlib import Path

import pytest

from litellm_supply_chain_audit import cli, scanner
from litellm_supply_chain_audit.scanner import ScanConfig, run_scan

BAD_VERSIONS = ["1.82.7", "1.82.8"]
CLEAN_VERSIONS = ["1.82.6", "1.82.9"]


def _install_fixture(site_packages: Path, version: str, layout: str = "dist-info") -> None:
    if layout == "dist-info":
        info = site_packages / f"litellm-{version}.dist-info"
        meta = info / "METADATA"
    else:
        info = site_packages / f"litellm-{version}-py3.11.egg-info"
        meta = info / "PKG-INFO"
    info.mkdir(parents=True)
    meta.write_text(f"Metadata-Version: 2.1\nName: litellm\nVersion: {version}\n", encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A hermetic machine: one fake interpreter, empty home and caches, clean hosts file.

    Each phase that would otherwise read the real host is pointed at tmp_path, so a
    litellm wheel sitting in the developer's own cache cannot flip a clean result.
    """
    home = tmp_path / "home"
    home.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData" / "Local"))

    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    monkeypatch.setattr(
        scanner,
        "discover_environments",
        lambda **_: [{"python": "fixture-python", "site_packages": [str(site_packages)]}],
    )
    monkeypatch.setattr(scanner, "find_pth_in_system_locations", lambda **_: [])
    monkeypatch.setattr(
        scanner, "scan_hosts_file_for_ioc", lambda: {"status": "ok", "matched_lines": []}
    )

    project = tmp_path / "project"
    project.mkdir()
    return {"home": home, "site_packages": site_packages, "project": project}


def _scan(project: Path) -> tuple[dict, int]:
    return run_scan(ScanConfig(scan_root=project, skip_docker=True, skip_processes=True))


@pytest.mark.parametrize("layout", ["dist-info", "egg-info"])
@pytest.mark.parametrize("version", BAD_VERSIONS)
def test_installed_bad_version_is_danger(env, version, layout):
    _install_fixture(env["site_packages"], version, layout)

    report, code = _scan(env["project"])

    assert code == 2
    assert report["summary"]["summary_level"] == "danger"
    [row] = report["phases"]["installed_litellm"]
    assert row["litellm_version"] == version
    assert row["compromised"] is True


@pytest.mark.parametrize("version", CLEAN_VERSIONS)
def test_installed_clean_version_is_not_flagged(env, version):
    _install_fixture(env["site_packages"], version)

    report, code = _scan(env["project"])

    # Any installed litellm is a warning by design; what must not happen is danger.
    assert code == 1
    assert report["summary"]["summary_level"] == "warning"
    [row] = report["phases"]["installed_litellm"]
    assert row["compromised"] is False


def test_no_litellm_is_clean(env):
    report, code = _scan(env["project"])

    assert code == 0
    assert report["summary"]["summary_level"] == "clean"
    assert report["phases"]["installed_litellm"] == []


@pytest.mark.parametrize("version", BAD_VERSIONS)
def test_cached_bad_wheel_is_danger(env, version):
    cache = env["home"] / ".cache" / "uv" / "wheels-v5"
    cache.mkdir(parents=True)
    (cache / f"litellm-{version}-py3-none-any.whl").write_bytes(b"")

    report, code = _scan(env["project"])

    assert code == 2
    assert len(report["phases"]["pip_uv_cache"]) == 1


@pytest.mark.parametrize("version", CLEAN_VERSIONS)
def test_cached_clean_wheel_is_ignored(env, version):
    cache = env["home"] / ".cache" / "uv" / "wheels-v5"
    cache.mkdir(parents=True)
    (cache / f"litellm-{version}-py3-none-any.whl").write_bytes(b"")

    report, code = _scan(env["project"])

    assert code == 0
    assert report["phases"]["pip_uv_cache"] == []


@pytest.mark.parametrize(("version", "expected"), [(BAD_VERSIONS[0], 2), (CLEAN_VERSIONS[0], 1)])
def test_cli_exit_code_and_json_contract(env, capsys, version, expected):
    _install_fixture(env["site_packages"], version)

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                str(env["project"]),
                "--json-only",
                "--no-report-file",
                "--no-docker",
                "--no-processes",
            ]
        )

    assert exc.value.code == expected
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["compromised_versions"] == BAD_VERSIONS
    assert report["phases"]["installed_litellm"][0]["litellm_version"] == version
