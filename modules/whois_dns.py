"""
modules/whois_dns.py
 
Task 2: WHOIS & DNS Enumeration Module
----------------------------------------
Performs passive reconnaissance on a target domain:
    1. WHOIS lookup           -> registrar, creation/expiry dates, owner org, name servers
    2. DNS enumeration        -> A, MX, TXT, NS records
    3. IP resolution          -> primary A record IP, with timestamp
 
Design notes for integration with the rest of the tool:
    - Exposes a single entry point: run(domain: str) -> dict
      recon.py calls this when the user passes --whois and/or --dns.
    - Every sub-task (whois, each DNS record type) is wrapped in its own
      try/except so one failure (e.g. WHOIS privacy protection, no MX
      records) never kills the rest of the scan. Failures are recorded
      under "errors" instead of raising.
    - Uses the standard `logging` module only (no handlers configured here) -
      so verbosity is controlled centrally by recon.py / config.py.
    - Depends on: python-whois, dnspython
        pip install python-whois dnspython
"""
 
import socket
import logging
from datetime import datetime, timezone
from typing import Optional
 
try:
    import whois  # python-whois package, imported as "whois"
except ImportError:
    whois = None
 
try:
    import dns.resolver
except ImportError:
    dns = None
 
try:
    import config  # project-wide settings (timeouts, etc.)
    DEFAULT_TIMEOUT = getattr(config, "DEFAULT_TIMEOUT", 5)
except ImportError:
    DEFAULT_TIMEOUT = 5
 
logger = logging.getLogger(__name__)
 
# DNS record types we care about for this task
DNS_RECORD_TYPES = ["A", "MX", "TXT", "NS"]
 
# ---------------------------------------------------------------------------
# Reference data used by the analysis layer below. These are simple
# substring-match signatures, not exhaustive - good enough to give an
# analyst a fast first impression, not a guaranteed identification.
# ---------------------------------------------------------------------------
 
KNOWN_REGISTRARS = [
    "godaddy", "namecheap", "markmonitor", "network solutions", "tucows",
    "enom", "name.com", "amazon registrar", "cloudflare", "pdr ltd",
    "ovh", "gandi", "ionos", "1&1", "hostinger", "publicdomainregistry",
    "namesilo", "dreamhost", "register.com", "google", "internet assigned",
    "dynadot", "porkbun", "squarespace domains", "google registry",
    "google domains", "hover", "hexonet", "csc",
]
 
DNS_PROVIDER_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "akam.net": "Akamai",
    "awsdns": "AWS Route 53",
    "azure-dns": "Azure DNS",
    "azuredns": "Azure DNS",
    "domaincontrol.com": "GoDaddy DNS",
    "google.com": "Google Authoritative DNS",   # e.g. ns1.google.com - Google's own infra NS
    "googledomains": "Google Domains",           # e.g. ns-cloud-*.googledomains.com
    "dnsmadeeasy": "DNS Made Easy",
    "digitalocean": "DigitalOcean DNS",
    "ns.namecheaphosting.com": "Namecheap DNS",
    "nsone.net": "NS1",
    "fastly.net": "Fastly",
    "cloudns.net": "CloudNS",
    "oraclevcn.com": "Oracle Cloud DNS",
    "oraclecloud.com": "Oracle Cloud DNS",
    "alidns.com": "Alibaba Cloud DNS",
    "hichina.com": "Alibaba Cloud DNS",
}
 
MX_PROVIDER_SIGNATURES = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "zoho": "Zoho Mail",
    "pphosted.com": "Proofpoint",
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "ironport": "Cisco IronPort",
    "cisco": "Cisco IronPort",
    "yahoodns": "Yahoo Mail",
    "qq.com": "Tencent QQ Mail",
    "messagingengine.com": "Fastmail",
    "protonmail.ch": "Proton Mail",
    "pmx.protonmail.ch": "Proton Mail",
    "icloud.com": "Apple iCloud Mail",
    "me.com": "Apple iCloud Mail",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "sparkpostmail.com": "SparkPost",
    "mtasv.net": "Postmark",
    "yandex.net": "Yandex",
    "yandex.ru": "Yandex",
}
 
TECH_SIGNATURES = {
    "google-site-verification": "Google",
    "apple-domain-verification": "Apple",
    "facebook-domain-verification": "Facebook",
    "atlassian-domain-verification": "Atlassian",
    "github-challenge": "GitHub",
    "github-verification": "GitHub",
    "gitlab-verification": "GitLab",
    "gitlab-pages-verification": "GitLab",
    "slack-domain-verification": "Slack",
    "dropbox-domain-verification": "Dropbox",
    "salesforce": "Salesforce",
    "hubspot": "HubSpot",
    "mailchimp": "Mailchimp",
    "mandrill": "Mailchimp",
    "docusign": "DocuSign",
    "onetrust": "OneTrust",
    "cisco-ci-domain-verification": "Cisco",
    "globalsign": "GlobalSign",
    "stripe-verification": "Stripe",
    "adobe-idp-site-verification": "Adobe",
    "adobe-sign-verification": "Adobe",
    "amazonses:": "AWS SES",
    "ms=": "Microsoft",
    "msft:": "Azure",
    "acme-challenge": "Let's Encrypt / ACME TLS validation",
}
 
# Common DKIM selectors to probe when a specific selector isn't known.
# This is best-effort: absence of these doesn't guarantee DKIM is unused,
# since selectors are arbitrary and provider-specific.
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "smtp"]
 
# Module-level resolver cache - avoids constructing a new dns.resolver.Resolver
# (and re-reading system DNS config) on every single query in this module.
_resolver_instance = None
 
 
def _get_resolver():
    """
    Returns a shared, pre-configured dns.resolver.Resolver instance.
    Created once per process and reused everywhere in this module that
    needs to run a DNS query (records, DMARC, DKIM, DNSSEC).
    """
    global _resolver_instance
    if dns is None:
        return None
    if _resolver_instance is None:
        _resolver_instance = dns.resolver.Resolver()
        _resolver_instance.lifetime = DEFAULT_TIMEOUT
        _resolver_instance.timeout = DEFAULT_TIMEOUT
    return _resolver_instance
 
 
def _get_whois_info(domain: str) -> dict:
    """
    Runs a WHOIS lookup for the domain.
    Returns a dict with the fields we care about, or an 'error' key if it fails.
    """
    if whois is None:
        msg = "python-whois library not installed (pip install python-whois)"
        logger.error(msg)
        return {"error": msg}
 
    try:
        logger.debug(f"Running WHOIS lookup for {domain}")
        w = whois.whois(domain)
 
        # python-whois sometimes returns lists (multiple registrars/dates found
        # across WHOIS servers) and sometimes single values - normalize both.
        def first_if_list(value):
            if isinstance(value, list) and value:
                return str(value[0])
            if value is None:
                return None
            return str(value)
 
        result = {
            "domain_name": first_if_list(w.domain_name) or domain,
            "registrar": first_if_list(w.registrar),
            "creation_date": first_if_list(w.creation_date),
            "expiration_date": first_if_list(w.expiration_date),
            "updated_date": first_if_list(w.updated_date),
            "name_servers": w.name_servers if w.name_servers else [],
            "org": first_if_list(getattr(w, "org", None)),
            "country": first_if_list(getattr(w, "country", None)),
            "emails": w.emails if isinstance(w.emails, list) else (
                [w.emails] if w.emails else []
            ),
        }
 
        if not result["registrar"] and not result["name_servers"]:
            logger.warning(
                f"WHOIS for {domain} returned mostly empty data "
                f"(may be privacy-protected or a WHOIS parsing gap)"
            )
 
        logger.info(f"WHOIS lookup succeeded for {domain}")
        return result
 
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        return {"error": str(e)}
 
 
def _get_dns_records(domain: str) -> dict:
    """
    Queries A, MX, TXT, and NS records for the domain (original core fields -
    unchanged for backward compatibility with recon.py/report.py), plus
    enriches the result with AAAA, CNAME, per-type TTLs, and a DNSSEC check.
 
    Each record type is queried independently so one missing type
    (e.g. no MX records) doesn't block the others.
 
    Returns:
        {
            "A": [...], "MX": [...], "TXT": [...], "NS": [...],   # original
            "AAAA": [...], "CNAME": [...],                         # new
            "ttls": {"A": 300, "MX": 3600, ...},                   # new
            "dnssec_enabled": True/False/None,                     # new
            "errors": {...},
        }
    """
    records = {rtype: [] for rtype in DNS_RECORD_TYPES}
    ttls = {}
    errors = {}
 
    if dns is None:
        msg = "dnspython library not installed (pip install dnspython)"
        logger.error(msg)
        return {**records, "AAAA": [], "CNAME": [], "ttls": {}, "dnssec_enabled": None, "errors": {"all": msg}}
 
    resolver = _get_resolver()
 
    # Original four types stay exactly as before, just now also capturing TTL.
    for rtype in DNS_RECORD_TYPES:
        try:
            logger.debug(f"Querying {rtype} records for {domain}")
            answers = resolver.resolve(domain, rtype)
            ttls[rtype] = answers.rrset.ttl if answers.rrset else None
 
            if rtype == "MX":
                records[rtype] = sorted(
                    [f"{a.preference} {a.exchange.to_text().rstrip('.')}" for a in answers]
                )
            elif rtype == "TXT":
                # TXT records come back as byte strings split into chunks - join them
                records[rtype] = [
                    b"".join(a.strings).decode(errors="replace") for a in answers
                ]
            else:  # A, NS
                records[rtype] = sorted([a.to_text().rstrip(".") for a in answers])
 
            logger.info(f"{rtype} lookup succeeded for {domain}: {len(records[rtype])} record(s)")
 
        except dns.resolver.NoAnswer:
            msg = f"No {rtype} records found"
            logger.warning(f"{msg} for {domain}")
            errors[rtype] = msg
        except dns.resolver.NXDOMAIN:
            msg = f"Domain {domain} does not exist"
            logger.error(msg)
            errors[rtype] = msg
            break  # no point checking other record types if the domain doesn't exist
        except Exception as e:
            logger.error(f"{rtype} lookup failed for {domain}: {e}")
            errors[rtype] = str(e)
 
    # New: AAAA (IPv6) and CNAME - queried the same defensive way, but kept
    # separate from DNS_RECORD_TYPES so the original keys/behavior above
    # are untouched.
    for extra_rtype in ("AAAA", "CNAME"):
        try:
            answers = resolver.resolve(domain, extra_rtype)
            ttls[extra_rtype] = answers.rrset.ttl if answers.rrset else None
            records[extra_rtype] = sorted([a.to_text().rstrip(".") for a in answers])
            logger.info(f"{extra_rtype} lookup succeeded for {domain}: {len(records[extra_rtype])} record(s)")
        except dns.resolver.NoAnswer:
            records[extra_rtype] = []
        except dns.resolver.NXDOMAIN:
            records[extra_rtype] = []
        except Exception as e:
            logger.debug(f"{extra_rtype} lookup failed for {domain}: {e}")
            records[extra_rtype] = []
            errors[extra_rtype] = str(e)
 
    # New: lightweight DNSSEC check - a DNSKEY record at the apex means the
    # zone at least publishes signing keys. This does NOT validate the full
    # chain of trust, just detects whether DNSSEC is plausibly in use.
    dnssec_enabled = None
    try:
        resolver.resolve(domain, "DNSKEY")
        dnssec_enabled = True
    except dns.resolver.NoAnswer:
        dnssec_enabled = False
    except dns.resolver.NXDOMAIN:
        dnssec_enabled = False
    except Exception as e:
        logger.debug(f"DNSSEC check failed for {domain}: {e}")
        dnssec_enabled = None
 
    return {
        **records,
        "ttls": ttls,
        "dnssec_enabled": dnssec_enabled,
        "errors": errors,
    }
 
 
def _resolve_ip(domain: str) -> str | None:
    """Resolves the domain's primary IP address using plain socket lookup."""
    try:
        ip = socket.gethostbyname(domain)
        logger.debug(f"Resolved {domain} -> {ip}")
        return ip
    except socket.gaierror as e:
        logger.warning(f"Could not resolve IP for {domain}: {e}")
        return None
 
 
def _parse_whois_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parses a WHOIS date string (as stringified by _get_whois_info) into a
    timezone-aware datetime. Returns None if parsing fails - never raises.
    """
    if not date_str or date_str in ("None", "null"):
        return None
 
    formats = (
        "%Y-%m-%d %H:%M:%S%z",      # e.g. "2024-08-14 04:00:00+00:00"
        "%Y-%m-%d %H:%M:%S.%f%z",   # e.g. "2024-08-14 04:00:00.123456+00:00"
        "%Y-%m-%d %H:%M:%S.%f",     # e.g. "2024-08-14 04:00:00.123456" (naive, str(datetime) w/ microseconds)
        "%Y-%m-%d %H:%M:%S",        # e.g. "2024-08-14 04:00:00" (naive - the common case: str(datetime))
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(date_str, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
 
    logger.debug(f"Could not parse WHOIS date: {date_str}")
    return None
 
 
def _categorize_domain_age(age_days: Optional[int]) -> str:
    """Buckets domain age into analyst-friendly brackets."""
    if age_days is None:
        return "Unknown"
    if age_days <= 30:
        return "0-30 days"
    if age_days <= 180:
        return "31-180 days"
    if age_days <= 365:
        return "181-365 days"
    if age_days <= 365 * 5:
        return "1-5 years"
    if age_days <= 365 * 10:
        return "5-10 years"
    return "10+ years"
 
 
def _analyze_domain(whois_info: dict) -> dict:
    """
    Interprets raw WHOIS data into an age profile, expiration risk,
    and registrar reputation check.
    """
    if "error" in whois_info:
        return {
            "registration_status": "Unknown (WHOIS lookup failed)",
            "age_days": None,
            "age_years": None,
            "age_category": "Unknown",
            "days_until_expiration": None,
            "expiring_soon": False,
            "registrar": None,
            "registrar_known": False,
        }
 
    now = datetime.now(timezone.utc)
    created = _parse_whois_date(whois_info.get("creation_date"))
    expires = _parse_whois_date(whois_info.get("expiration_date"))
 
    age_days = (now - created).days if created else None
    age_years = round(age_days / 365.25, 2) if age_days is not None else None
    age_category = _categorize_domain_age(age_days)
 
    days_until_expiration = (expires - now).days if expires else None
    expiring_soon = days_until_expiration is not None and 0 <= days_until_expiration <= 90
 
    registrar = whois_info.get("registrar")
    registrar_known = bool(
        registrar and any(known in registrar.lower() for known in KNOWN_REGISTRARS)
    )
 
    return {
        "registration_status": "Registered",
        "age_days": age_days,
        "age_years": age_years,
        "age_category": age_category,
        "days_until_expiration": days_until_expiration,
        "expiring_soon": expiring_soon,
        "registrar": registrar,
        "registrar_known": registrar_known,
    }
 
 
def _analyze_dns(dns_info: dict) -> dict:
    """Interprets DNS records for redundancy, hosting/DNS provider hints, and CDN likelihood."""
    a_records = dns_info.get("A", [])
    aaaa_records = dns_info.get("AAAA", [])
    cname_records = dns_info.get("CNAME", [])
    ns_records = dns_info.get("NS", [])
    ttls = dns_info.get("ttls", {})
 
    detected_providers = set()
    for ns in ns_records:
        ns_lower = ns.lower()
        for signature, provider in DNS_PROVIDER_SIGNATURES.items():
            if signature in ns_lower:
                detected_providers.add(provider)
 
    dns_providers = sorted(detected_providers) if detected_providers else ["Unknown / custom"]
 
    # CDN probability heuristic: a known CDN/edge provider, OR multiple A
    # records combined with a short TTL (typical of dynamically load-balanced
    # edge infrastructure), suggests a CDN is likely in front of the domain.
    cdn_signal_providers = {"Cloudflare", "Akamai", "Fastly"}
    a_ttl = ttls.get("A")
    short_ttl = a_ttl is not None and a_ttl <= 300
    cdn_probability = "High" if (cdn_signal_providers & detected_providers) else (
        "Medium" if (len(a_records) > 1 and short_ttl) else "Low"
    )
 
    # A domain can be validly registered in WHOIS yet have zero live DNS
    # records - either NXDOMAIN at the DNS layer, or simply no records of
    # any kind configured yet. Both are worth flagging distinctly: this
    # pattern (registered, but dark) is common for domains staged ahead of
    # a phishing/malware campaign, as well as for brand-new legitimate
    # sites whose nameservers just haven't propagated yet.
    mx_records = dns_info.get("MX", [])
    no_dns_presence = not any([a_records, aaaa_records, cname_records, ns_records, mx_records])
    nxdomain_detected = any(
        "does not exist" in str(err).lower() for err in dns_info.get("errors", {}).values()
    )

    return {
        "a_record_count": len(a_records),
        "aaaa_record_count": len(aaaa_records),
        "cname_present": bool(cname_records),
        "cname_target": cname_records[0] if cname_records else None,
        "possible_load_balancing_or_cdn": len(a_records) > 1,
        "no_dns_presence": no_dns_presence,
        "nxdomain_detected": nxdomain_detected,
        "ttls": ttls,
        "dnssec_enabled": dns_info.get("dnssec_enabled"),
        "dns_providers": dns_providers,
        "cdn_probability": cdn_probability,
    }
 
 
SPF_QUALIFIER_MEANINGS = {
    "-all": "Hard fail - mail from unlisted servers should be rejected outright.",
    "~all": "Soft fail - mail from unlisted servers is accepted but flagged/suspect.",
    "?all": "Neutral - explicitly makes no statement about unlisted servers.",
    "+all": "Pass-all - allows mail from ANY server; effectively disables SPF's protection.",
}
 
 
def _check_spf(txt_records: list) -> dict:
    """Detects an SPF record among the domain's own TXT records and parses its qualifier."""
    for txt in txt_records:
        stripped = txt.strip().lower()
        if stripped.startswith("v=spf1"):
            qualifier = None
            qualifier_meaning = None
            for q in ("-all", "~all", "?all", "+all"):
                if q in stripped:
                    qualifier = q
                    qualifier_meaning = SPF_QUALIFIER_MEANINGS[q]
                    break
            return {
                "status": "Present",
                "record": txt,
                "qualifier": qualifier,
                "qualifier_meaning": qualifier_meaning,
            }
    return {"status": "Missing", "record": None, "qualifier": None, "qualifier_meaning": None}
 
 
def _check_dmarc(domain: str) -> dict:
    """
    DMARC records live at _dmarc.<domain>, not the apex domain, so this
    performs a separate, independent TXT lookup for that subdomain.
    """
    resolver = _get_resolver()
    if resolver is None:
        return {"status": "Unknown", "record": None}
 
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for a in answers:
            txt = b"".join(a.strings).decode(errors="replace")
            if txt.strip().lower().startswith("v=dmarc1"):
                return {"status": "Present", "record": txt}
        return {"status": "Missing", "record": None}
    except dns.resolver.NoAnswer:
        return {"status": "Missing", "record": None}
    except dns.resolver.NXDOMAIN:
        return {"status": "Missing", "record": None}
    except Exception as e:
        logger.debug(f"DMARC lookup failed for {domain}: {e}")
        return {"status": "Unknown", "record": None}
 
 
def _check_dkim(domain: str) -> dict:
    """
    DKIM records live at <selector>._domainkey.<domain>. The selector is
    provider-specific and not discoverable without prior knowledge, so this
    only probes a handful of common selectors. Never reports "Missing" -
    absence under common selectors is reported as "Undetermined" since a
    provider-specific selector may still be in use.
    """
    resolver = _get_resolver()
    if resolver is None:
        return {"status": "Unknown", "selector_found": None}
 
    for selector in COMMON_DKIM_SELECTORS:
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            return {"status": "Present", "selector_found": selector}
        except Exception:
            continue
 
    return {"status": "Undetermined", "selector_found": None}
 
 
def _analyze_email_security(domain: str, dns_info: dict) -> dict:
    """Combines SPF, DKIM, and DMARC checks with a plain-language explanation."""
    spf = _check_spf(dns_info.get("TXT", []))
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain)
 
    return {
        "spf": {
            **spf,
            "meaning": "SPF lists which mail servers are allowed to send email for this "
                       "domain. Missing SPF makes it easier to spoof emails from this domain.",
        },
        "dkim": {
            **dkim,
            "meaning": "DKIM cryptographically signs outgoing mail so receivers can verify "
                       "it wasn't altered. Selectors are provider-specific, so 'Undetermined' "
                       "means none of the common selectors matched - not proof DKIM is absent.",
        },
        "dmarc": {
            **dmarc,
            "meaning": "DMARC tells receiving mail servers what to do with messages that "
                       "fail SPF/DKIM (reject, quarantine, or allow). Missing DMARC means "
                       "spoofed mail using this domain may reach inboxes unchecked.",
        },
    }
 
 
def _analyze_mx(mx_records: list) -> dict:
    """Identifies the likely email provider from MX record hostnames."""
    detected = set()
    for mx in mx_records:
        mx_lower = mx.lower()
        for signature, provider in MX_PROVIDER_SIGNATURES.items():
            if signature in mx_lower:
                detected.add(provider)
 
    return {
        "mx_record_count": len(mx_records),
        "detected_providers": sorted(detected) if detected else (
            ["Unknown provider"] if mx_records else ["No mail servers configured"]
        ),
    }
 
 
def _detect_technologies(txt_records: list) -> list:
    """Scans TXT records for known third-party service verification signatures."""
    detected = set()
    for txt in txt_records:
        txt_lower = txt.lower()
        for signature, tech in TECH_SIGNATURES.items():
            if signature in txt_lower:
                detected.add(tech)
    return sorted(detected)
 
 
def _build_analysis(domain: str, whois_info: dict, dns_info: dict) -> dict:
    """Assembles the full analysis section from all the individual analyzers."""
    return {
        "domain_analysis": _analyze_domain(whois_info),
        "dns_analysis": _analyze_dns(dns_info),
        "email_security": _analyze_email_security(domain, dns_info),
        "mx_analysis": _analyze_mx(dns_info.get("MX", [])),
        "detected_technologies": _detect_technologies(dns_info.get("TXT", [])),
    }
 
 
def _generate_security_findings(analysis: dict, whois_info: dict) -> list:
    """
    Turns the structured analysis into a flat list of analyst-friendly
    findings. Each finding has:
        finding  - human-readable description
        severity - INFO, LOW, MEDIUM, or HIGH
        category - WHOIS, DNS, EMAIL, INFRASTRUCTURE, or TECHNOLOGY
    """
    findings = []
    domain_a = analysis["domain_analysis"]
    dns_a = analysis["dns_analysis"]
    email_a = analysis["email_security"]
 
    def add(finding, severity, category):
        findings.append({"finding": finding, "severity": severity, "category": category})
 
    # --- WHOIS / domain age & expiration ---
    if "error" in whois_info:
        add("WHOIS lookup failed or the domain is privacy-protected.", "LOW", "WHOIS")
    else:
        age_cat = domain_a["age_category"]
        if age_cat == "0-30 days":
            add("Domain was registered within the last 30 days.", "HIGH", "WHOIS")
        elif age_cat == "31-180 days":
            add("Domain is under 6 months old.", "MEDIUM", "WHOIS")
        elif age_cat == "181-365 days":
            add("Domain is under 1 year old.", "LOW", "WHOIS")
        elif age_cat in ("1-5 years", "5-10 years", "10+ years"):
            add(f"Domain registration is {age_cat} old, appears established.", "INFO", "WHOIS")
 
        if domain_a["expiring_soon"]:
            days = domain_a["days_until_expiration"]
            severity = "HIGH" if days is not None and days <= 30 else "MEDIUM"
            add(f"Domain registration expires in {days} day(s).", severity, "WHOIS")
 
        if not domain_a["registrar_known"]:
            add("Registrar is not on the common/well-known registrar list.", "LOW", "WHOIS")
 
    # --- DNS / infrastructure ---
    if domain_a["registration_status"] == "Registered" and dns_a.get("no_dns_presence"):
        detail = " (NXDOMAIN)" if dns_a.get("nxdomain_detected") else ""
        add(
            f"Domain is registered in WHOIS but has no live DNS records{detail} - "
            "consistent with infrastructure staged for later use (legitimate setup in "
            "progress, or a domain parked ahead of a phishing/malware campaign).",
            "HIGH", "DNS",
        )

    if dns_a["possible_load_balancing_or_cdn"]:
        add("Multiple A records present, indicating redundancy or load balancing.", "INFO", "INFRASTRUCTURE")
 
    for provider in dns_a["dns_providers"]:
        if provider != "Unknown / custom":
            add(f"{provider} authoritative DNS detected.", "INFO", "INFRASTRUCTURE")
    if dns_a["dns_providers"] == ["Unknown / custom"]:
        add("DNS provider could not be identified from NS record signatures.", "INFO", "DNS")
 
    if dns_a["cdn_probability"] == "High":
        add("High confidence a CDN sits in front of this domain's origin server.", "INFO", "INFRASTRUCTURE")
 
    if dns_a["dnssec_enabled"] is False:
        add("DNSSEC does not appear to be enabled for this domain.", "LOW", "DNS")
    elif dns_a["dnssec_enabled"] is True:
        add("DNSSEC appears to be enabled (DNSKEY record found).", "INFO", "DNS")
 
    # --- Email security ---
    spf = email_a["spf"]
    if spf["status"] == "Present":
        if spf["qualifier"] == "+all":
            add("SPF record present but uses '+all', which allows any server to send mail as this domain.", "HIGH", "EMAIL")
        elif spf["qualifier"] == "~all":
            add("SPF policy present (~all soft fail).", "INFO", "EMAIL")
        elif spf["qualifier"] == "-all":
            add("SPF policy present (-all hard fail) - strongest SPF enforcement.", "INFO", "EMAIL")
        else:
            add("SPF record present with a neutral or unrecognized qualifier.", "LOW", "EMAIL")
    else:
        add("No SPF record found. Email spoofing protection may be reduced.", "MEDIUM", "EMAIL")
 
    if email_a["dmarc"]["status"] == "Present":
        add("DMARC policy configured.", "INFO", "EMAIL")
    elif email_a["dmarc"]["status"] == "Missing":
        add("No DMARC policy found. Email spoofing protection may be reduced.", "MEDIUM", "EMAIL")
 
    if email_a["dkim"]["status"] == "Present":
        add(f"DKIM record found (selector: {email_a['dkim']['selector_found']}).", "INFO", "EMAIL")
 
    # Suspicious combination: brand-new domain + no SPF/DMARC is a stronger
    # phishing-infrastructure signal than either factor alone.
    if domain_a["age_category"] == "0-30 days" and spf["status"] == "Missing" and email_a["dmarc"]["status"] == "Missing":
        add("Newly registered domain with no SPF or DMARC - a pattern often seen in phishing infrastructure.", "HIGH", "EMAIL")
 
    # --- Technology ---
    for tech in analysis.get("detected_technologies", []):
        add(f"Third-party integration detected via TXT record: {tech}.", "INFO", "TECHNOLOGY")
 
    return findings
 
 
def _calculate_risk(analysis: dict, whois_info: dict, dns_info: dict) -> tuple:
    """
    Weighted risk scoring model. Rather than just summing finding severities,
    this looks directly at the underlying signals so specific factors can be
    weighted according to how much they actually matter for risk:

        Domain age (new domains are the single biggest signal)  up to 30
        Expiration proximity                                    up to 15
        WHOIS unavailable/privacy-protected                     5
        Registrar not on the known list                         5
        Missing SPF                                             10
        Missing DMARC                                           10
        DKIM undetermined                                       3
        Unknown DNS provider                                    5
        Registered domain with no live DNS records at all        20
        DNS lookup failures (per failed record type)            up to 10
        Suspicious combination (new domain + no SPF/DMARC)       +15 bonus

    Positive infrastructure signals (multiple A records, known DNS
    provider, DNSSEC enabled) do not add risk - they're informational.

    Every point added is also recorded in `breakdown` (factor + points),
    so the caller can explain *why* the score landed where it did instead
    of only reporting the final number.

    Returns: (score 0-100, level, breakdown) where level is
    Low/Medium/High/Critical per: 0-20 Low, 21-50 Medium, 51-75 High,
    76-100 Critical. breakdown is a list of {"factor": str, "points": int},
    sorted highest-impact first.
    """
    score = 0
    breakdown = []  # [{"factor": "...", "points": N}, ...] - only non-zero contributions
    domain_a = analysis["domain_analysis"]
    dns_a = analysis["dns_analysis"]
    email_a = analysis["email_security"]

    def contribute(points: int, factor: str) -> None:
        """Adds points to the running score and records why, if it actually mattered."""
        nonlocal score
        if points:
            score += points
            breakdown.append({"factor": factor, "points": points})

    # Domain age
    age_weights = {
        "0-30 days": 30, "31-180 days": 18, "181-365 days": 8,
        "1-5 years": 2, "5-10 years": 0, "10+ years": 0, "Unknown": 10,
    }
    age_category = domain_a["age_category"]
    age_points = age_weights.get(age_category, 0)
    if age_category == "Unknown":
        contribute(age_points, "Domain age could not be determined (WHOIS unavailable/unparsed)")
    elif age_points:
        contribute(age_points, f"Domain is relatively new ({age_category} old)")

    # Expiration proximity
    if domain_a["expiring_soon"]:
        days = domain_a["days_until_expiration"] or 0
        points = 15 if days <= 30 else 8
        contribute(points, f"Domain registration expires soon ({days} day(s))")

    # WHOIS / registrar
    if "error" in whois_info:
        contribute(5, "WHOIS lookup failed or domain is privacy-protected")
    elif not domain_a["registrar_known"]:
        contribute(5, "Registrar is not on the known/common registrar list")

    # Email security
    if email_a["spf"]["status"] != "Present":
        contribute(10, "No SPF record found")
    elif email_a["spf"].get("qualifier") == "+all":
        contribute(10, "SPF record uses '+all', which allows any server to send mail")
    if email_a["dmarc"]["status"] != "Present":
        contribute(10, "No DMARC policy found")
    if email_a["dkim"]["status"] == "Undetermined":
        contribute(3, "DKIM signing could not be confirmed under common selectors")

    # DNS infrastructure
    if dns_a["dns_providers"] == ["Unknown / custom"]:
        contribute(5, "DNS provider could not be identified from NS records")

    if domain_a["registration_status"] == "Registered" and dns_a.get("no_dns_presence"):
        contribute(20, "Domain is registered but has no live DNS records (registered-but-dark)")

    dns_failure_count = len(dns_info.get("errors", {}))
    if dns_failure_count:
        points = min(dns_failure_count * 3, 10)
        contribute(points, f"{dns_failure_count} DNS record type(s) failed to resolve")

    # Suspicious combination bonus (mirrors the finding generated above)
    if (age_category == "0-30 days"
            and email_a["spf"]["status"] != "Present"
            and email_a["dmarc"]["status"] != "Present"):
        contribute(15, "Newly registered domain with no SPF/DMARC - common phishing pattern")

    score = max(0, min(score, 100))

    if score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    elif score <= 75:
        level = "High"
    else:
        level = "Critical"

    # Largest contributors first, so the explanation leads with what matters most.
    breakdown.sort(key=lambda item: item["points"], reverse=True)

    return score, level, breakdown


def _explain_risk_score(score: int, level: str, breakdown: list) -> str:
    """
    Turns the numeric score and its contributing factors into a short,
    analyst-readable sentence - e.g. what an SOC dashboard tooltip would
    show instead of a bare number.

    Only the top 3 contributing factors are named explicitly to keep this
    brief; the rest are folded into a count if present.
    """
    if not breakdown:
        return f"Risk is {level} ({score}/100). No significant risk factors were detected."

    top = breakdown[:3]
    reasons = "; ".join(f"{item['factor']} (+{item['points']})" for item in top)

    remaining = len(breakdown) - len(top)
    if remaining > 0:
        reasons += f"; and {remaining} more minor factor(s)"

    return f"Risk is {level} ({score}/100), mainly due to: {reasons}."


 
def _generate_recommendations(analysis: dict, security_findings: list, risk_level: str) -> list:
    """
    Builds next-step recommendations driven by what was actually found,
    rather than a fixed list handed back regardless of the scan results.
    """
    recommendations = []
    domain_a = analysis["domain_analysis"]
    dns_a = analysis["dns_analysis"]
    email_a = analysis["email_security"]
 
    if domain_a["age_category"] == "Unknown":
        recommendations.append("WHOIS unavailable - perform a historical WHOIS lookup to trace registration history.")
 
    if domain_a["age_category"] in ("0-30 days", "31-180 days"):
        recommendations.append("Domain is young - run a domain/IP reputation lookup before trusting this asset.")

    if domain_a["registration_status"] == "Registered" and dns_a.get("no_dns_presence"):
        recommendations.append(
            "Domain is registered but has no live DNS presence - monitor for DNS activation over "
            "the next few days/weeks, since this pattern is common for domains staged ahead of a "
            "phishing or malware campaign as well as for legitimate sites still being set up."
        )
 
    if email_a["spf"]["status"] != "Present":
        recommendations.append("Publish an SPF record to specify authorized sending mail servers.")
    elif email_a["spf"].get("qualifier") == "+all":
        recommendations.append("Tighten the SPF policy - '+all' permits any server to send mail as this domain.")
 
    if email_a["dmarc"]["status"] != "Present":
        recommendations.append("Implement a DMARC policy (starting at p=quarantine) to reduce email spoofing risk.")
 
    if email_a["dkim"]["status"] == "Undetermined":
        recommendations.append("Confirm the domain's actual DKIM selector with the mail provider to verify signing is active.")
 
    if "Cloudflare" in dns_a["dns_providers"] or dns_a["cdn_probability"] in ("High", "Medium"):
        recommendations.append("A CDN/proxy is likely in front of the origin - attempt origin IP discovery (historical DNS, SSL cert SANs, subdomain misses).")
 
    if dns_a["possible_load_balancing_or_cdn"]:
        recommendations.append("Multiple A records found - check whether this reflects CDN edge nodes or genuine load-balanced origins.")
 
    if dns_a["dnssec_enabled"] is False:
        recommendations.append("Consider enabling DNSSEC to protect against DNS spoofing/cache poisoning.")
 
    if domain_a["expiring_soon"]:
        recommendations.append("Domain nears expiration - flag for re-verification, since expired domains are commonly re-registered by attackers.")
 
    # Baseline recon next-steps that apply regardless of findings above.
    recommendations.extend([
        "Run subdomain enumeration to map the full attack surface.",
        "Perform an ASN lookup to identify the hosting network/provider.",
        "Retrieve the TLS certificate to check validity and SAN entries.",
        "Query VirusTotal and AbuseIPDB for domain/IP reputation history.",
        "Search for exposed services via Shodan/Censys.",
    ])
 
    # De-duplicate while preserving order (in case a condition above
    # produces overlapping advice).
    seen = set()
    deduped = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            deduped.append(rec)
 
    return deduped
 
 
def run(domain: str) -> dict:
    """
    Main entry point called by recon.py for --whois and --dns flags.
 
    Matches the project-wide interface expected by report.py:
        run(domain) -> dict with "whois" and "dns" keys (plus extras below).
 
    Args:
        domain: target domain, e.g. "example.com"
 
    Returns:
        dict with keys:
            domain       - the target domain
            timestamp    - UTC ISO timestamp of when the scan ran
            resolved_ip  - primary IP the domain resolves to
            whois        - dict of WHOIS fields (or {"error": ...})
            dns          - dict of DNS record lists + any per-type errors
            status       - "success", "partial", or "error"
    """
    logger.info(f"Starting WHOIS & DNS enumeration for {domain}")
 
    whois_info = _get_whois_info(domain)
    dns_info = _get_dns_records(domain)
 
    whois_failed = "error" in whois_info
    dns_failed = bool(dns_info.get("errors")) and not any(
        dns_info[rtype] for rtype in DNS_RECORD_TYPES
    )
 
    if not whois_failed and not dns_failed:
        status = "success"
    elif whois_failed and dns_failed:
        status = "error"
    else:
        status = "partial"
 
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resolved_ip": _resolve_ip(domain),
        "whois": whois_info,
        "dns": dns_info,
        "status": status,
    }
 
    # --- Analysis layer: interprets the raw data above into SOC-style
    # findings. Wrapped in try/except so an analysis bug never takes down
    # the core recon output above - result already has everything recon.py
    # and report.py depend on before we even get here.
    try:
        analysis = _build_analysis(domain, whois_info, dns_info)
        security_findings = _generate_security_findings(analysis, whois_info)
        risk_score, risk_level, risk_breakdown = _calculate_risk(analysis, whois_info, dns_info)
        risk_explanation = _explain_risk_score(risk_score, risk_level, risk_breakdown)
        recommendations = _generate_recommendations(analysis, security_findings, risk_level)

        result["analysis"] = analysis
        result["security_findings"] = security_findings
        result["risk_score"] = risk_score
        result["risk_level"] = risk_level
        result["risk_breakdown"] = risk_breakdown
        result["risk_explanation"] = risk_explanation
        result["recommendations"] = recommendations
    except Exception as e:
        logger.error(f"Analysis layer failed for {domain}: {e}")
        result["analysis"] = {}
        result["security_findings"] = []
        result["risk_score"] = None
        result["risk_level"] = "Unknown"
        result["risk_breakdown"] = []
        result["risk_explanation"] = "Risk analysis could not be completed due to an internal error."
        result["recommendations"] = []
 
    logger.info(f"Finished WHOIS & DNS enumeration for {domain} - status: {status}")
    return result


def _format_summary(result: dict) -> str:
    """
    Renders the scan result as a clean, human-readable report for terminal
    output. This is purely a display helper - it doesn't add, remove, or
    alter any of the underlying data; report.py/recon.py should keep
    consuming the dict from run() directly rather than this string.
    """
    lines = []

    def header(title: str) -> None:
        lines.append("")
        lines.append(f"--- {title} ---")

    domain = result.get("domain", "unknown")
    status = result.get("status", "unknown")
    whois_info = result.get("whois", {})
    dns_info = result.get("dns", {})
    analysis = result.get("analysis", {}) or {}
    domain_a = analysis.get("domain_analysis", {})
    dns_a = analysis.get("dns_analysis", {})
    email_a = analysis.get("email_security", {})
    mx_a = analysis.get("mx_analysis", {})
    tech = analysis.get("detected_technologies", [])
    findings = result.get("security_findings", []) or []
    recommendations = result.get("recommendations", []) or []

    width = 60
    lines.append("=" * width)
    lines.append(f" WHOIS & DNS Reconnaissance Report: {domain}".ljust(width))
    lines.append("=" * width)
    lines.append(f"Status: {status}  |  Scanned: {result.get('timestamp', 'n/a')}")
    lines.append(f"Resolved IP: {result.get('resolved_ip') or 'Unresolved'}")

    header("WHOIS")
    if "error" in whois_info:
        lines.append(f"Lookup failed: {whois_info['error']}")
    else:
        registrar = domain_a.get("registrar") or "Unknown"
        known_tag = "" if not domain_a.get("registrar_known") else " (known registrar)"
        lines.append(f"Registrar:  {registrar}{known_tag}")
        age_years = domain_a.get("age_years")
        age_txt = f"{age_years} years old ({domain_a.get('age_category', 'Unknown')})" if age_years is not None else "Unknown"
        lines.append(f"Created:    {whois_info.get('creation_date', 'Unknown')}  ->  {age_txt}")
        days_left = domain_a.get("days_until_expiration")
        expiry_flag = "  \u26a0 EXPIRING SOON" if domain_a.get("expiring_soon") else ""
        expiry_txt = f"{days_left} day(s) left" if days_left is not None else "Unknown"
        lines.append(f"Expires:    {whois_info.get('expiration_date', 'Unknown')}  ->  {expiry_txt}{expiry_flag}")

    header("DNS")
    lines.append(f"A records:     {', '.join(dns_info.get('A', [])) or 'None'}")
    lines.append(f"AAAA records:  {', '.join(dns_info.get('AAAA', [])) or 'None'}")
    lines.append(f"DNS provider:  {', '.join(dns_a.get('dns_providers', ['Unknown']))}")
    lines.append(f"CDN likely:    {dns_a.get('cdn_probability', 'Unknown')}")
    dnssec = dns_a.get("dnssec_enabled")
    lines.append(f"DNSSEC:        {'Enabled' if dnssec else 'Disabled' if dnssec is False else 'Unknown'}")

    header("Email Security")
    spf = email_a.get("spf", {})
    dmarc = email_a.get("dmarc", {})
    dkim = email_a.get("dkim", {})
    spf_txt = spf.get("status", "Unknown")
    if spf.get("qualifier"):
        spf_txt += f" ({spf['qualifier']})"
    lines.append(f"SPF:    {spf_txt}")
    lines.append(f"DMARC:  {dmarc.get('status', 'Unknown')}")
    lines.append(f"DKIM:   {dkim.get('status', 'Unknown')}")
    lines.append(f"MX provider(s): {', '.join(mx_a.get('detected_providers', ['Unknown']))}")
    if tech:
        lines.append(f"Detected tech:  {', '.join(tech)}")

    header("Risk")
    lines.append(f"Score: {result.get('risk_score')}/100  ({result.get('risk_level', 'Unknown')})")
    lines.append(result.get("risk_explanation", ""))
    risk_breakdown = result.get("risk_breakdown", []) or []
    if risk_breakdown:
        lines.append("Contributing factors:")
        for item in risk_breakdown:
            lines.append(f"  +{item['points']:<3} {item['factor']}")

    if findings:
        header(f"Findings ({len(findings)} total)")
        severity_order = ["HIGH", "MEDIUM", "LOW", "INFO"]
        by_severity = {s: [] for s in severity_order}
        for f in findings:
            by_severity.setdefault(f.get("severity", "INFO"), []).append(f)
        for severity in severity_order:
            group = by_severity.get(severity, [])
            if not group:
                continue
            lines.append(f"[{severity}] ({len(group)})")
            for f in group:
                category = f.get("category", "")
                lines.append(f"  - {f.get('finding', '')}" + (f"  [{category}]" if category else ""))

    if recommendations:
        header(f"Recommendations ({len(recommendations)} total)")
        for i, rec in enumerate(recommendations, start=1):
            lines.append(f"{i}. {rec}")

    lines.append("")
    lines.append("=" * width)
    return "\n".join(lines)


# Allows standalone testing: python modules/whois_dns.py example.com
if __name__ == "__main__":
    import sys
    import json

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    args = sys.argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]

    if len(args) != 1:
        print("Usage: python whois_dns.py <domain> [--json]")
        sys.exit(1)

    output = run(args[0])

    if as_json:
        print(json.dumps(output, indent=2, default=str))
    else:
        print(_format_summary(output))