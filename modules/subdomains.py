"""
modules/subdomains.py
Task 3: Subdomain Enumeration (Passive Recon)

Sources:
    1. HackerTarget   -> free API, no key needed, very reliable
    2. crt.sh         -> Certificate Transparency logs
    3. AlienVault OTX -> Passive DNS (optional API key)

Each source is queried independently so if one fails the others
still return results.
"""
import json
import logging
import os
import socket
import time
import re

import requests

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (Recon-Tool/1.0)"}


# Source 1: HackerTarget (most reliable)

def query_hackertarget(domain, timeout=10):
    """Query HackerTarget hostsearch API. Free, no key, reliable."""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

    try:
        logger.debug("Querying HackerTarget: %s", url)
        resp = requests.get(url, timeout=timeout, headers=HEADERS)

        if resp.status_code != 200:
            logger.warning("HackerTarget returned %d", resp.status_code)
            return subdomains

        # Returns CSV: subdomain,ip per line
        # If rate-limited it returns "error ..." text
        if resp.text.startswith("error"):
            logger.warning("HackerTarget: %s", resp.text.strip())
            return subdomains

        for line in resp.text.strip().split("\n"):
            parts = line.split(",")
            if parts and parts[0].strip().endswith(domain):
                subdomains.add(parts[0].strip().lower())

        logger.info("HackerTarget: found %d entries", len(subdomains))

    except requests.exceptions.RequestException as e:
        logger.warning("HackerTarget failed: %s", e)

    return subdomains


# Source 2: crt.sh (Certificate Transparency)

def query_crtsh(domain, timeout=15):
    """Query crt.sh. Can be slow/flaky, so short timeout with 1 retry."""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    for attempt in range(1, 3):
        try:
            logger.debug("Querying crt.sh (attempt %d)", attempt)
            resp = requests.get(url, timeout=timeout, headers=HEADERS)
            resp.raise_for_status()

            data = json.loads(resp.text)
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    # Skip wildcards like *.example.com
                    clean = name.lstrip("*.")
                    if clean.endswith(domain):
                        subdomains.add(clean)

            logger.info("crt.sh: found %d entries", len(subdomains))
            return subdomains

        except requests.exceptions.RequestException as e:
            logger.debug("crt.sh failed (attempt %d): %s", attempt, e)
            if attempt < 2:
                time.sleep(2)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("crt.sh returned bad data: %s", e)
            break

    return subdomains


# Source 3: AlienVault OTX

def query_otx(domain, timeout=15):
    """Query AlienVault OTX passive DNS. Works better with OTX_API_KEY env var."""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = dict(HEADERS)

    api_key = os.environ.get("OTX_API_KEY")
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        logger.debug("Querying OTX")
        resp = requests.get(url, timeout=timeout, headers=headers)

        if resp.status_code == 429:
            logger.warning("OTX rate-limited (429)")
            return subdomains

        resp.raise_for_status()
        data = resp.json()

        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").strip().lower()
            if hostname.endswith(domain):
                subdomains.add(hostname)

        logger.info("OTX: found %d entries", len(subdomains))

    except requests.exceptions.RequestException as e:
        logger.warning("OTX failed: %s", e)

    return subdomains


# IP Resolution

def resolve_ip(hostname, timeout=3.0):
    """Resolve a hostname to IP. Returns IP string or 'unresolved'."""
    if hostname.startswith("*."):
        return "wildcard"
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout):
        return "unresolved"


# Entry point

def run(domain):
    """Main entry point called by recon.py."""
    logger.info("Starting subdomain enumeration for: %s", domain)

    # Query all sources
    ht_results = query_hackertarget(domain)
    crtsh_results = query_crtsh(domain)
    otx_results = query_otx(domain)

    all_subdomains = sorted(ht_results | crtsh_results | otx_results)

    # Resolve IPs
    logger.info("Resolving IPs for %d subdomains", len(all_subdomains))
    ip_map = {sub: resolve_ip(sub) for sub in all_subdomains}

    logger.info("Subdomain enumeration complete: %d found", len(all_subdomains))

    return {
        "domain": domain,
        "total_found": len(all_subdomains),
        "sources": {
            "hackertarget": sorted(ht_results),
            "crt.sh": sorted(crtsh_results),
            "alienvault_otx": sorted(otx_results),
        },
        "subdomains": all_subdomains,
        "ip_resolution": ip_map,
    }