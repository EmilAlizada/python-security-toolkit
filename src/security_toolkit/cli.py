from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .hashing import SUPPORTED_ALGORITHMS, hash_file
from .headers import analyze_headers, fetch_headers
from .integrity import create_manifest, verify_manifest
from .iocs import extract_indicators
from .log_analysis import summarize_auth_log


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sec-toolkit",
        description="Defensive Python security utilities.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser("hash", help="Calculate a cryptographic file hash")
    hash_parser.add_argument("path", type=Path)
    hash_parser.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default="sha256",
    )

    integrity_parser = subparsers.add_parser(
        "integrity",
        help="Create or verify a file-integrity manifest",
    )
    integrity_sub = integrity_parser.add_subparsers(dest="integrity_command", required=True)

    create_parser = integrity_sub.add_parser("create", help="Create a SHA-256 baseline")
    create_parser.add_argument("root", type=Path)
    create_parser.add_argument("manifest", type=Path)

    verify_parser = integrity_sub.add_parser("verify", help="Verify a SHA-256 baseline")
    verify_parser.add_argument("root", type=Path)
    verify_parser.add_argument("manifest", type=Path)

    headers_parser = subparsers.add_parser(
        "headers",
        help="Review response security headers for one URL",
    )
    headers_parser.add_argument("url")
    headers_parser.add_argument("--timeout", type=float, default=5.0)

    ioc_parser = subparsers.add_parser("iocs", help="Extract common indicators from text")
    ioc_source = ioc_parser.add_mutually_exclusive_group(required=True)
    ioc_source.add_argument("file", nargs="?", type=Path)
    ioc_source.add_argument("--text")

    auth_parser = subparsers.add_parser(
        "auth-log",
        help="Summarize common authentication log events",
    )
    auth_parser.add_argument("path", type=Path)

    return parser


def _print_integrity(root: Path, manifest: Path) -> int:
    result = verify_manifest(root, manifest)
    if result.clean:
        print("integrity: clean")
        return 0

    for label, values in (
        ("modified", result.modified),
        ("missing", result.missing),
        ("unexpected", result.unexpected),
    ):
        for value in values:
            print(f"{label}: {value}")
    return 1


def _print_iocs(text: str) -> None:
    indicators = extract_indicators(text)
    for label, values in (
        ("ip", indicators.ip_addresses),
        ("url", indicators.urls),
        ("domain", indicators.domains),
        ("sha256", indicators.sha256),
    ):
        for value in values:
            print(f"{label}: {value}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "hash":
            print(hash_file(args.path, args.algorithm))
            return 0

        if args.command == "integrity":
            if args.integrity_command == "create":
                manifest = create_manifest(args.root, args.manifest)
                print(f"manifest: {args.manifest} ({len(manifest['files'])} files)")
                return 0
            return _print_integrity(args.root, args.manifest)

        if args.command == "headers":
            final_url, headers = fetch_headers(args.url, args.timeout)
            is_https = final_url.lower().startswith("https://")
            print(f"url: {final_url}")
            missing = False
            for finding in analyze_headers(headers, is_https=is_https):
                state = "present" if finding.present else "missing"
                print(f"{state}: {finding.header}")
                missing = missing or not finding.present
            return 1 if missing else 0

        if args.command == "iocs":
            text = args.text if args.text is not None else args.file.read_text(encoding="utf-8")
            _print_iocs(text)
            return 0

        if args.command == "auth-log":
            summary = summarize_auth_log(args.path.read_text(encoding="utf-8", errors="replace"))
            print(f"failed: {summary.failed}")
            print(f"accepted: {summary.accepted}")
            print(f"invalid_user: {summary.invalid_user}")
            for source, count in summary.failed_sources:
                print(f"failed_source: {source} ({count})")
            return 0

    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
