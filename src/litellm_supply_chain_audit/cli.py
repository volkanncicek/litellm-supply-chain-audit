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
    p.add_argument("--no-docker", action="store_true", help="Skip Docker image name scan")
    p.add_argument("--no-processes", action="store_true", help="Skip process/socket scan")
    p.add_argument("--json-only", action="store_true", help="Print JSON report to stdout only")
    p.add_argument(
        "--no-report-file",
        action="store_true",
        help="Do not write litellm-supply-chain-audit-*.json",
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
        skip_docker=args.no_docker,
        skip_processes=args.no_processes,
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
