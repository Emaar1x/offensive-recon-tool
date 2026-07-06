"""
modules/subdomains.py
Task 3: Subdomain Enumeration (Passive Recon)
Enumerates subdomains for a target domain using two free, public, passive
sources, then resolves each result to an IP address:
    1. crt.sh          -> Certificate Transparency logs
    2. AlienVault OTX  -> Passive DNS / threat intel API
    3. IP Resolution   -> standard DNS lookup for each found subdomain

This module is called by recon.py as: modules.subdomains.run(domain)
Logging and console output are handled by recon.py itself, so this module
only uses the `logging` module (never print()) and returns a plain dict.

Setup note (per teammate, not committed to the repo):
    Get a free OTX API key at https://otx.alienvault.com/settings
    then set it as an environment variable:
        Windows:   setx OTX_API_KEY "your_key_here"
        Mac/Linux: export OTX_API_KEY="your_key_here"
    The unauthenticated OTX endpoint works too, but is more likely to be
    rate-limited (HTTP 429).
"""
import json
import logging
import os
import socket
import time

import requests

logger = logging.getLogger(__name__)

# Source 1: crt.sh (Certificate Transparency logs)

def query_crtsh(domain: str, timeout: int = 40) -> set:
    """
    Queries crt.sh for certificates issued to *.domain and extracts
    the common names / SANs, which reveal subdomains.

    crt.sh is a free community service and can be slow at times, so a
    generous timeout is used, with one retry before giving up.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Recon-Tool/1.0)"}

    for attempt in range(1, 3):
        try:
            logger.debug("Querying crt.sh (attempt %d): %s", attempt, url)
            resp = requests.get(url, timeout=timeout, headers=headers)
            resp.raise_for_status()

            # crt.sh sometimes returns malformed/concatenated JSON,
            # so we parse defensively.
            data = json.loads(resp.text)

            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain):
                        subdomains.add(name)

            logger.info("crt.sh: found %d entries", len(subdomains))
            return subdomains

        except requests.exceptions.RequestException as e:
            logger.debug("crt.sh request failed (attempt %d): %s", attempt, e)
            if attempt == 2:
                logger.warning("crt.sh: giving up after 2 attempts")
                break
            time.sleep(3)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("crt.sh returned unparsable data: %s", e)
            break

    return subdomains


# Source 2: AlienVault OTX (passive DNS)


def query_otx(domain: str, timeout: int = 45) -> set:
    """
    Queries AlienVault OTX's passive DNS API for records related to domain.
    Uses OTX_API_KEY from the environment if set (recommended, see module
    docstring above); falls back to an unauthenticated request otherwise.
    """
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"User-Agent": "Mozilla/5.0 (Recon-Tool/1.0)"}

    api_key = os.environ.get("OTX_API_KEY")
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
        logger.debug("Using OTX API key from environment variable")
    else:
        logger.debug("No OTX_API_KEY found; using unauthenticated request")

    for attempt in range(1, 3):
        try:
            logger.debug("Querying OTX (attempt %d): %s", attempt, url)
            resp = requests.get(url, timeout=timeout, headers=headers)

            if resp.status_code == 429:
                logger.debug("OTX rate-limited (429) on attempt %d", attempt)
                if attempt == 2:
                    logger.warning("OTX: giving up after rate-limiting")
                    break
                time.sleep(10)
                continue

            resp.raise_for_status()
            data = resp.json()

            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if hostname.endswith(domain):
                    subdomains.add(hostname)

            logger.info("OTX: found %d entries", len(subdomains))
            return subdomains

        except requests.exceptions.RequestException as e:
            logger.debug("OTX request failed (attempt %d): %s", attempt, e)
            if attempt == 2:
                logger.warning("OTX: giving up after 2 attempts")
                break
            time.sleep(5)
            continue
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("OTX returned unparsable data: %s", e)
            break

    return subdomains


# Step 3: IP Resolution

def resolve_ip(hostname: str, timeout: float = 3.0) -> str:
    """
    Resolves a single hostname to its IP address via standard DNS lookup.
    Returns the IP as a string, or a status string ("wildcard" /
    "unresolved") when a real lookup isn't possible or fails.
    """
    if hostname.startswith("*."):
        return "wildcard"

    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout):
        return "unresolved"


def resolve_all_ips(subdomain_list: list) -> dict:
    """Resolves IP addresses for a list of subdomains -> {subdomain: ip/status}."""
    return {sub: resolve_ip(sub) for sub in subdomain_list}


# Entry point expected by recon.py: modules.subdomains.run(domain)

def run(domain: str) -> dict:
    """
    Main entry point called by recon.py.

    Returns a dict shaped for the reporting module (Task 5):
        {
            "domain": str,
            "total_found": int,
            "sources": {"crt.sh": [...], "alienvault_otx": [...]},
            "subdomains": [...],          # merged, deduplicated, sorted
            "ip_resolution": {sub: ip_or_status, ...},
        }
    """
    logger.info("Starting subdomain enumeration for: %s", domain)

    crtsh_results = query_crtsh(domain)
    otx_results = query_otx(domain)
    all_subdomains = sorted(crtsh_results | otx_results)

    logger.info("Resolving IP addresses for %d unique subdomains", len(all_subdomains))
    ip_map = resolve_all_ips(all_subdomains)

    logger.info("Subdomain enumeration complete: %d found", len(all_subdomains))

    return {
        "domain": domain,
        "total_found": len(all_subdomains),
        "sources": {
            "crt.sh": sorted(crtsh_results),
            "alienvault_otx": sorted(otx_results),
        },
        "subdomains": all_subdomains,
        "ip_resolution": ip_map,
    }