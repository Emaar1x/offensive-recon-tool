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


def run_module(name, module, domain, results, **kwargs):
    """Run a single module safely (catch all errors)."""
    try:
        logging.info("Running module: %s", name)
        if name == "portscan" and "port_spec" in kwargs:
            data = module.run(domain, kwargs["port_spec"])
        else:
            data = module.run(domain)
        results[name] = data
        logging.info("Module '%s' done.", name)
    except Exception as e:
        logging.error("Module '%s' failed: %s", name, e)
        results[name] = {"error": str(e)}


def print_portscan_help():
    """Print portscan module usage and examples."""
    help_text = """
╔══════════════════════════════════════════════════════════════════╗
║                    PORT SCAN MODULE - HELP                       ║
╚══════════════════════════════════════════════════════════════════╝

PORT SPECIFICATIONS:
  ┌─────────────────────┬──────────────────────────────────────────┐
  │ Spec                │ Description                              │
  ├─────────────────────┼──────────────────────────────────────────┤
  │ default/top100      │ Top 100 most common ports                │
  │ top1000             │ Ports 1-1000                             │
  │ 80,443,8080         │ Comma-separated list                     │
  │ 1-1000              │ Range                                    │
  │ 1-100,443,8000-9000 │ Mixed range and list                     │
  │ 22                  │ Single port                              │
  └─────────────────────┴──────────────────────────────────────────┘

EXAMPLES:
  # Basic scan (top 100 ports)
  python recon.py --ports example.com

  # Top 1000 ports
  python recon.py --ports example.com --port-spec top1000

  # Specific ports
  python recon.py --ports example.com --port-spec 80,443,8080

  # Port range
  python recon.py --ports example.com --port-spec 1-100

  # Mixed range and list
  python recon.py --ports example.com --port-spec 1-100,443,8000-9000

  # Single port
  python recon.py --ports example.com --port-spec 22

  # With verbosity
  python recon.py --ports example.com -v
  python recon.py --ports example.com -vv

  # Standalone testing
  python modules/portscan.py example.com
  python modules/portscan.py example.com top1000
  python modules/portscan.py example.com 80,443,8080

COMMON PORT GROUPS:
  Web:         80, 443, 8080, 8443, 8000
  Database:    3306, 5432, 27017, 6379, 1433
  Remote:      22, 23, 3389, 5900
  Mail:        25, 110, 143, 465, 587, 993, 995
  Windows:     135, 139, 445, 3389

PERFORMANCE NOTES:
  - Top 100 ports:  ~5-8 seconds
  - Top 1000 ports: ~60-75 seconds
  - Custom lists:   ~2-5 seconds
  - Speed: ~14 ports/second on Windows

╔══════════════════════════════════════════════════════════════════╗
║  For more details, check: README.md or python recon.py --help    ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(help_text)


def main():
    parser = argparse.ArgumentParser(
        description="Offensive Recon Tool - A modular reconnaissance framework.",
        add_help=True
    )
    
    # Make domain optional with nargs='?'
    parser.add_argument("domain", nargs='?', help="Target domain (e.g. example.com)")
    
    parser.add_argument("--whois", action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Subdomain discovery")
    parser.add_argument("--ports", action="store_true", help="Port scan")
    parser.add_argument("--port-spec", default="top100",
                        help="Port specification: top100, top1000, 80,443, 1-1000, 1-100,200,300-400")
    parser.add_argument("--tech", action="store_true", help="Technology detection")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--help-ports", action="store_true",
                        help="Show port scan module usage and examples")
    parser.add_argument("-o", "--output", choices=["json", "txt", "html"], default="json",
                        help="Report format (default: json)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbosity (-v for INFO, -vv for DEBUG)")

    args = parser.parse_args()
    
    # Show portscan help if requested (no domain needed)
    if args.help_ports:
        print_portscan_help()
        sys.exit(0)
    
    # Check if domain is provided (now optional, so we need to check)
    if not args.domain:
        parser.print_help()
        print("\n[!] Error: domain is required unless using --help-ports")
        print("[!] Usage: python recon.py <domain> [options]")
        print("[!] For port scan help: python recon.py --help-ports")
        sys.exit(1)
    
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
        print("[!] For port scan help: python recon.py --help-ports")
        sys.exit(1)

    # Run selected modules
    results = {}
    print(f"\n[*] Starting recon on {domain}\n")
    
    start_time = time.time()

    try:
        for name, module in modules_to_run.items():
            print(f"  [*] {name}...")
            run_module(name, module, domain, results, port_spec=args.port_spec)
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

        # Quick Summary
        summary = []
        if "subdomains" in results and "total_found" in results["subdomains"]:
            summary.append(f"{results['subdomains']['total_found']} subdomains")
        if "portscan" in results and "total_open" in results["portscan"]:
            summary.append(f"{results['portscan']['total_open']} open ports")
        if "techdetect" in results and "technologies" in results["techdetect"]:
            summary.append(f"{len(results['techdetect']['technologies'])} technologies")
        if "whois_dns" in results and "risk_level" in results["whois_dns"]:
            summary.append(f"Risk: {results['whois_dns']['risk_level']}")
            
        if summary:
            print(f"\n[*] Summary: {' | '.join(summary)}")

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user (Ctrl+C).")
        sys.exit(130)

    elapsed = time.time() - start_time
    print(f"\n[*] Done in {elapsed:.1f} seconds.\n")


if __name__ == "__main__":
    main()