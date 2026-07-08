Offensive Recon Tool

A modular, command-line reconnaissance framework built for **authorized**
penetration testing and security assessments. It brings together passive
WHOIS/DNS enumeration, subdomain discovery, port scanning, technology
fingerprinting, and multi-format reporting behind a single CLI.

> ⚠️ **Legal Disclaimer**
> This tool is intended **only** for use against systems you own or have
> **explicit, written authorization** to test. Running reconnaissance or
> scans against domains/hosts without permission may violate the Computer
> Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent
> laws in your jurisdiction. The authors and contributors accept no
> liability for misuse of this tool. Always get authorization in writing
> before testing.

## Features

| Module | What it does |
|---|---|
| **WHOIS & DNS** (`--whois`, `--dns`) | Registrar/creation/expiry lookup, A/AAAA/MX/TXT/NS/CNAME records, DNSSEC check, SPF/DKIM/DMARC email-security analysis, domain-age risk scoring, and analyst-style findings & recommendations |
| **Subdomains** (`--subdomains`) | Passive enumeration via HackerTarget, crt.sh (Certificate Transparency), and AlienVault OTX, with IP resolution for each discovered host |
| **Port Scan** (`--ports`) | Multi-threaded TCP connect scanning, service/version fingerprinting from banners, SSL/TLS certificate inspection, flexible port specs (top100, top1000, ranges, lists) |
| **Tech Detection** (`--tech`) | HTTP header analysis + optional `builtwith` fingerprinting for CMS/framework/CDN identification |
| **Reporting** (`-o`) | Generates a report in `json`, `txt`, or `html` combining the output of every module that ran |

## Requirements

- Python 3.10+ (developed/tested on Python 3.12)
- pip

## Installation

```bash
git clone https://github.com/Emaar1x/offensive-recon-tool.git
cd offensive-recon-tool
pip install -r requirements.txt
```

`requirements.txt` installs: `python-whois`, `dnspython`, `requests`,
`python-nmap`, `builtwith`, `jinja2`, `pytest`.

> Note: the port scanner itself is a **pure Python socket-based scanner**
> and does not currently call out to the `nmap` binary or the
> `python-nmap` library — see [Known Limitations](#known-limitations).

## Usage

```bash
# Run everything
python recon.py --all example.com

# Run individual modules
python recon.py --whois example.com
python recon.py --dns example.com
python recon.py --subdomains example.com
python recon.py --ports example.com
python recon.py --tech example.com

# Combine modules
python recon.py --whois --dns --tech example.com

# Verbosity
python recon.py --all example.com -v     # INFO level
python recon.py --all example.com -vv    # DEBUG level

# Choose a report format (default: json)
python recon.py --all example.com -o html
python recon.py --all example.com -o txt

# Custom port specifications
python recon.py --ports example.com --port-spec top1000
python recon.py --ports example.com --port-spec 80,443,8080
python recon.py --ports example.com --port-spec 1-1000
python recon.py --ports example.com --port-spec 1-100,443,8000-9000

# Port-scan module help (works standalone, no domain required)
python recon.py --help-ports

# General CLI help
python recon.py --help
```

Every module can also be run standalone for quick debugging, e.g.:

```bash
python modules/whois_dns.py example.com [--json]
python modules/portscan.py example.com [port-spec]
```

## Project Structure
```
offensive-recon-tool/
├── recon.py                # CLI entry point: argument parsing, logging, dispatch
├── config.py                # Shared settings (paths, default timeout)
├── modules/
│   ├── __init__.py
│   ├── whois_dns.py         # Task 2 - WHOIS & DNS enumeration + risk analysis
│   ├── subdomains.py        # Task 3 - Passive subdomain enumeration
│   ├── portscan.py          # Task 4 - TCP port scanning & banner grabbing
│   ├── techdetect.py        # Task 5 - Technology/header fingerprinting
│   └── report.py            # Task 5 - json/txt/html report generation
├── tests/
│   └── test_recon.py        # Task 6 - Full automated test suite (pytest)
├── logs/                     # Timestamped run logs (git-ignored)
├── reports/                   # Generated reports (git-ignored)
├── requirements.txt
├── README.md
```
## Module Interface
Every recon module exposes a single entry point consumed by `recon.py`:

```python
def run(domain: str) -> dict:
    ...
```
`portscan.py` additionally accepts an optional port specification:
```python
def run(domain: str, port_spec: str = "default") -> dict:
    ...
```
`report.py` exposes:
```python
def generate(domain: str, results: dict, fmt: str = "json") -> str:
    """Returns the filepath of the generated report, or "" on failure."""
```
This contract is what lets `recon.py` dispatch to any module without
knowing its internals, and it's exactly what the Task 6 test suite
validates for every module.

## Known Limitations

- **Port scanner does not use `nmap`.** Despite `python-nmap` being listed
  in `requirements.txt`, `modules/portscan.py` implements its own
  multi-threaded raw-socket TCP connect scanner and does not import or
  shell out to `nmap`. Functionally this works well and is fully
  cross-platform, but it means scan accuracy/speed differs from an actual
  `nmap` scan (e.g. no SYN/stealth scanning, no OS fingerprinting).
- **Subdomain sources are passive and rate-limited.** HackerTarget and
  AlienVault OTX apply rate limits on their free tiers; on repeated runs
  against the same domain in a short window you may see fewer results
  than expected. This is a source-side limitation, not a bug.
- **`builtwith` may return little/nothing for many sites.** It relies on
  a static signature database that isn't always current; header-based
  detection in `techdetect.py` is used as a more reliable fallback.
- **DKIM detection is best-effort.** DKIM selectors are provider-specific
  and not publicly discoverable; `whois_dns.py` only probes a handful of
  common selectors, so a `"status": "Undetermined"` result does **not**
  mean DKIM is absent.
- **WHOIS output shape varies by TLD/registrar.** Some registries return
  list-valued fields (e.g. multiple creation dates from different WHOIS
  servers); this is normalized to a single value where possible but may
  occasionally pick the wrong entry for uncommon TLDs.

## Testing

```bash
python -m pytest tests/ -v
```

## Contributing

This is a 6-person team project. Each contributor owns one task/module.

| # | Task | Files |
|---|------|-------|
| 1 | Project setup, CLI, logging | `recon.py`, `config.py` |
| 2 | WHOIS & DNS | `modules/whois_dns.py` |
| 3 | Subdomains | `modules/subdomains.py` |
| 4 | Port scanning | `modules/portscan.py` |
| 5 | Tech detection & reports | `modules/techdetect.py`, `modules/report.py` |
| 6 | README & testing | `README.md`, `tests/` |