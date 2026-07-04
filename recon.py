#!/usr/bin/env python3
"""
recon.py - Main entry point for the Offensive Recon Tool.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime

from modules import whois_dns, subdomains, portscan, techdetect, report

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")


def setup_logging(verbosity=0):
    """Set up console + file logging."""
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    os.makedirs(LOGS_DIR, exist_ok=True)
    log_file = os.path.join(LOGS_DIR, datetime.now().strftime("recon_%Y%m%d_%H%M%S.log"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file),
        ],
    )
    logging.debug("Log file: %s", log_file)


def run_module(name, module, domain, results):
    """Run a single module safely (catch all errors)."""
    try:
        logging.info("Running module: %s", name)
        data = module.run(domain)
        results[name] = data
        logging.info("Module '%s' done.", name)
    except Exception as e:
        logging.error("Module '%s' failed: %s", name, e)
        results[name] = {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="Offensive Recon Tool - A modular reconnaissance framework."
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--whois", action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Subdomain discovery")
    parser.add_argument("--ports", action="store_true", help="Port scan")
    parser.add_argument("--tech", action="store_true", help="Technology detection")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("-o", "--output", choices=["json", "txt", "html"], default="json",
                        help="Report format (default: json)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbosity (-v for INFO, -vv for DEBUG)")

    args = parser.parse_args()
    setup_logging(args.verbose)

    domain = args.domain
    logging.info("Target: %s", domain)

    # Which modules to run
    modules_to_run = {}
    if args.whois or args.dns or args.all:
        modules_to_run["whois_dns"] = whois_dns
    if args.subdomains or args.all:
        modules_to_run["subdomains"] = subdomains
    if args.ports or args.all:
        modules_to_run["portscan"] = portscan
    if args.tech or args.all:
        modules_to_run["techdetect"] = techdetect

    if not modules_to_run:
        parser.print_help()
        print("\n[!] No module selected. Use --all or pick at least one.")
        sys.exit(1)

    # Run selected modules
    results = {}
    print(f"\n[*] Starting recon on {domain}\n")

    for name, module in modules_to_run.items():
        print(f"  [*] {name}...")
        run_module(name, module, domain, results)
        print(f"  [+] {name} done.")

    # Generate report
    print(f"\n[*] Generating report...")
    try:
        report_path = report.generate(domain, results, fmt=args.output)
        if report_path:
            print(f"[+] Report saved: {report_path}")
        else:
            print("[!] Report module not yet implemented (Task 5).")
    except Exception as e:
        print(f"[-] Report failed: {e}")

    print("\n[*] Done.\n")


if __name__ == "__main__":
    main()
