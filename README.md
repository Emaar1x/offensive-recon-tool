# Offensive Recon Tool

Modular reconnaissance tool for security testing.

## Setup

```bash
git clone https://github.com/Emaar1x/offensive-recon-tool.git
cd offensive-recon-tool
pip install -r requirements.txt
```

## Usage

```bash
python recon.py --all example.com
python recon.py --whois example.com
python recon.py --dns example.com
python recon.py --subdomains example.com
python recon.py --ports example.com
python recon.py --tech example.com
python recon.py --all example.com -v     # verbose
python recon.py --all example.com -vv    # debug
```

## Module Interface

Each module exposes: `run(domain) -> dict`

## Tasks

| # | Task | Files |
|---|------|-------|
| 1 | Project setup, CLI, logging | recon.py, config.py |
| 2 | WHOIS & DNS | modules/whois_dns.py |
| 3 | Subdomains | modules/subdomains.py |
| 4 | Port scanning | modules/portscan.py |
| 5 | Tech detection & reports | modules/techdetect.py, modules/report.py |
| 6 | README & testing | README.md, tests/ |
