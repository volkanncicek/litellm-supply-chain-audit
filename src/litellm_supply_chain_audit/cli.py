"""CLI entrypoint."""

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanConfig, report_to_text, run_scan, write_report


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Audit local Python environments for the March 2026 litellm PyPI incident "
            "(known-bad versions, litellm_init.pth, related manifests and caches)."
        ),
    )
    p.add_argument(
        "scan_root",
        nargs="?",
        default=None,
        help="Directory to scan (default: user home)",
    )
    p.add_argument(
        "--venv-walk-depth",
        type=int,
        default=8,
        help="Depth-limited venv discovery under scan_root via pyvenv.cfg (default: 8; 0 disables)",
    )
    p.add_argument(
        "--pth-max-depth",
        type=int,
        default=4,
        help=(
            "Recursive litellm_init.pth search depth under scan_root "
            "(default: 4; 0 disables)"
        ),
    )
    p.add_argument(
        "--pth-max-hits",
        type=int,
        default=50,
        help="Maximum number of litellm_init.pth IOC findings to keep (default: 50).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress and skipped-path info to stderr.",
    )
    p.add_argument("--no-docker", action="store_true", help="Skip Docker image name scan")
    p.add_argument("--no-processes", action="store_true", help="Skip process/socket scan")
    p.add_argument("--json-only", action="store_true", help="Print JSON report to stdout only")
    p.add_argument(
        "--no-report-file",
        action="store_true",
        help="Do not write litellm-supply-chain-audit-*.json",
    )
    p.add_argument(
        "--cache-max-files",
        type=int,
        default=100_000,
        help="Cache scanner hard cap for visited filenames (budget is split across cache roots).",
    )
    p.add_argument(
        "--cache-max-hits",
        type=int,
        default=200,
        help="Cache scanner maximum number of findings to keep.",
    )
    p.add_argument(
        "--python-info-timeout-seconds",
        type=float,
        default=5.0,
        help="Timeout for subprocess calls used to discover site-packages (default: 5s).",
    )
    p.add_argument(
        "--docker-timeout-seconds",
        type=float,
        default=15.0,
        help="Timeout for `docker image ls` (default: 15s).",
    )
    p.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Directory for the JSON report (default: scan root)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    try:
        home = Path.home()
        root = Path(args.scan_root).expanduser() if args.scan_root else home
        root = root.resolve()
    except OSError:
        print("Error: invalid scan path.", file=sys.stderr)
        sys.exit(3)

    if not root.is_dir():
        print(f"Error: not a directory or not accessible: {root}", file=sys.stderr)
        sys.exit(3)

    cfg = ScanConfig(
        scan_root=root,
        venv_walk_depth=args.venv_walk_depth,
        pth_max_depth=args.pth_max_depth,
        pth_max_hits=args.pth_max_hits,
        skip_docker=args.no_docker,
        skip_processes=args.no_processes,
        verbose=bool(args.verbose),
        cache_max_files=args.cache_max_files,
        cache_max_hits=args.cache_max_hits,
        python_info_timeout_seconds=args.python_info_timeout_seconds,
        docker_timeout_seconds=args.docker_timeout_seconds,
    )

    try:
        report, code = run_scan(cfg)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

    report_dir = args.report_dir or root
    if not args.no_report_file:
        try:
            path = write_report(report, report_dir)
            report["summary"]["report_path"] = str(path)
        except OSError as e:
            report["summary"]["report_write_error"] = str(e)

    if args.json_only:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(report_to_text(report), end="")

    sys.exit(code)


if __name__ == "__main__":
    main()
