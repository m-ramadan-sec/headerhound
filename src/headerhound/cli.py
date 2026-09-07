"""Command-line interface for HeaderHound."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .analyzer import assess
from .client import FetchError, ScanClient
from .models import ScanResult
from .output import render_json, render_table
from .safety import TargetError, ensure_public_target, normalize_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerhound",
        description="Safely audit HTTP response security headers for one URL.",
    )
    parser.add_argument("url", help="Absolute http:// or https:// URL to scan")
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Report format (default: table)",
    )
    parser.add_argument(
        "--json",
        dest="format",
        action="store_const",
        const="json",
        help="Alias for --format json",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=10.0,
        metavar="SECONDS",
        help="Per-request timeout (default: 10)",
    )
    parser.add_argument(
        "--max-redirects",
        type=_nonnegative_int,
        default=5,
        metavar="COUNT",
        help="Maximum redirects to follow (default: 5)",
    )
    parser.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Permit loopback, private, and reserved targets; only use on authorized systems",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (not recommended)",
    )
    parser.add_argument(
        "--min-interval",
        type=_nonnegative_float,
        default=0.2,
        metavar="SECONDS",
        help="Minimum interval before a request (default: 0.2)",
    )
    parser.add_argument(
        "--fail-under",
        type=_score,
        metavar="SCORE",
        help="Exit with status 1 when the completed scan score is below SCORE (0-100)",
    )
    parser.add_argument(
        "--min-score",
        dest="fail_under",
        type=_score,
        metavar="SCORE",
        help="Alias for --fail-under SCORE",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high"),
        help="Exit with status 1 when a finding meets or exceeds this severity",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        target = normalize_url(args.url)
        ensure_public_target(target, allow_private=args.allow_private)
        response = ScanClient(
            timeout=args.timeout,
            max_redirects=args.max_redirects,
            follow_redirects=not args.no_redirects,
            verify_tls=not args.insecure,
            min_interval=args.min_interval,
            allow_private=args.allow_private,
        ).fetch(target)
        result = assess(
            target=target,
            final_url=response.final_url,
            status_code=response.status_code,
            headers=response.headers,
            redirects=response.redirects,
            cookies=response.cookies,
            initial_url=response.initial_url,
        )
    except (TargetError, FetchError, ValueError) as exc:
        _write_error(str(exc), args.format)
        return 2

    print(render_json(result) if args.format == "json" else render_table(result))
    if args.fail_under is not None and result.score < args.fail_under:
        return 1
    if args.fail_on and _has_severity(result, args.fail_on):
        return 1
    return 0


def _write_error(message: str, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps({"error": message}), file=sys.stderr)
    else:
        print(f"headerhound: error: {message}", file=sys.stderr)


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _nonnegative_float(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return number


def _nonnegative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return number


def _score(value: str) -> int:
    number = _nonnegative_int(value)
    if number > 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return number


def _has_severity(result: ScanResult, threshold: str) -> bool:
    """Return whether a ScanResult has a finding at the selected threshold."""
    ranks = {"info": 0, "low": 1, "medium": 2, "high": 3}
    return any(ranks[finding.severity.value] >= ranks[threshold] for finding in result.findings)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
