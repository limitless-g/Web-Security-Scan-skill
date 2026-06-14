#!/usr/bin/env python3
"""
Web Security Scanner v8.0 — CLI Entry Point.

Usage:
    python cli.py --url https://target.com
    python cli.py --url https://target.com --policy pci-dss --compliance pci
    python cli.py --url https://target.com --passive-only --no-browser
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from scanner import WebSecurityScanner
from src.logging import log


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all CLI options."""
    ap = argparse.ArgumentParser(
        description="Web Security Scanner v7.5 — Production-Grade DAST Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --url https://example.com
  python cli.py --url https://example.com --policy pci-dss --compliance pci --fail-on critical
  python cli.py --url https://example.com --passive-only --no-browser
  python cli.py --url https://api.example.com --policy api-only
        """,
    )

    # Required
    ap.add_argument("--url", required=True, help="Target URL to scan")

    # Output
    ap.add_argument("--output", default="report.json", help="Output file path (default: report.json)")

    # Policy
    ap.add_argument(
        "--policy", default="full",
        choices=["safe", "owasp-top10", "pci-dss", "full", "quick", "api-only"],
        help="Scan policy preset (default: full)",
    )

    # Crawl
    ap.add_argument("--max-pages", type=int, default=150, help="Max pages to crawl (default: 150)")
    ap.add_argument("--no-spa", action="store_true", help="Disable SPA/JS rendering")

    # Scan mode
    ap.add_argument("--passive-only", action="store_true",
                    help="Passive analysis only — no attack traffic")
    ap.add_argument("--no-browser", action="store_true",
                    help="Curl-only mode — no Playwright required")

    # Timing
    ap.add_argument("--timeout", type=int, default=15000,
                    help="Request timeout in ms (default: 15000)")

    # OOB
    ap.add_argument("--oob-port", type=int, default=8889,
                    help="OOB callback server port (default: 8889)")

    # Logging
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                    help="Logging level (default: INFO)")

    # CI/CD
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "critical", "high", "medium"],
                    help="Pipeline exit code trigger (default: none)")

    # Compliance
    ap.add_argument("--compliance", default="",
                    choices=["", "pci", "hipaa", "soc2", "iso27001"],
                    help="Generate compliance report for specified framework")

    # Report
    ap.add_argument("--no-html", action="store_true",
                    help="Skip HTML report generation")

    # Advanced
    ap.add_argument("--internal", action="store_true",
                    help="Internal network target (adjusts security baseline)")
    ap.add_argument("--proxy", default="",
                    help="HTTP/SOCKS proxy (e.g., http://corp-proxy:8080)")
    ap.add_argument("--resume", action="store_true",
                    help="Resume from last checkpoint")
    ap.add_argument("--custom-header", action="append", default=[],
                    help="Custom request header (Key:Value), repeatable")

    return ap


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Handle missing URL
    if not args.url:
        parser.print_help()
        sys.exit(1)

    # Parse custom headers
    custom_headers = {}
    for h in args.custom_header:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    scanner = WebSecurityScanner(
        target_url=args.url,
        policy=args.policy,
        output=args.output,
        max_pages=args.max_pages,
        timeout=args.timeout,
        no_spa=args.no_spa,
        passive_only=args.passive_only,
        oob_port=args.oob_port,
        log_level=args.log_level,
        fail_on=args.fail_on,
        compliance=args.compliance,
        html_report=not args.no_html,
        no_browser=args.no_browser,
        proxy=args.proxy,
        resume=args.resume,
        is_internal=args.internal,
        custom_headers=custom_headers,
    )

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        log.warning("Scan interrupted by user")
        asyncio.run(scanner.stop())
        sys.exit(130)

    exit_code = scanner.get_exit_code()
    exit_map = {"critical": 4, "high": 3, "medium": 2, "none": 0}

    if args.fail_on != "none" and exit_code >= exit_map.get(args.fail_on, 0):
        sys.exit(exit_code)
    sys.exit(0)


if __name__ == "__main__":
    main()
