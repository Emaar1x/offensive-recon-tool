"""
techdetect.py - Technology detection (Task 5).

Interface:
    run(domain) -> dict with "technologies" list and "headers".
"""

# def run(domain):
#     # TODO: Task 5 teammate implements this
#     return {"technologies": [], "headers": {}, "status": "not_implemented"}







"""
techdetect.py - Technology detection (Task 5).

Interface:
    run(domain) -> dict with "technologies" list and "headers".

Strategy:
    1. Try builtwith (if installed) for a broad technology fingerprint
       (CMS, JS frameworks, analytics, web servers, etc.).
    2. Independently grab the raw HTTP response headers with requests,
       since these are useful on their own (server banner, security
       headers, cookies) and builtwith may fail on some targets.
    3. Merge everything into a single de-duplicated technology list
       plus the raw headers dict, and never let one failure crash the
       other (so partial results are still returned).
"""

import logging

import requests

try:
    import builtwith
    HAS_BUILTWITH = True
except ImportError:
    HAS_BUILTWITH = False

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (compatible; ReconTool/1.0)"


def _normalize_url(domain):
    """Return a usable URL, defaulting to https with an http fallback."""
    if domain.startswith("http://") or domain.startswith("https://"):
        return [domain]
    return [f"https://{domain}", f"http://{domain}"]


def _fetch_headers(domain):
    """Fetch HTTP response headers for the domain. Returns (headers_dict, final_url)."""
    last_error = None
    for url in _normalize_url(domain):
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
            )
            return dict(resp.headers), resp.url
        except requests.RequestException as e:
            last_error = e
            logger.debug("Request to %s failed: %s", url, e)
            continue
    if last_error:
        logger.warning("Could not reach %s over http(s): %s", domain, last_error)
    return {}, None


def _detect_from_headers(headers):
    """Derive simple technology hints directly from raw headers."""
    hints = []

    server = headers.get("Server")
    if server:
        hints.append(server)

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        hints.append(powered_by)

    if "cf-ray" in {k.lower() for k in headers}:
        hints.append("Cloudflare")

    if any(k.lower() == "set-cookie" and "wordpress" in v.lower()
           for k, v in headers.items()):
        hints.append("WordPress")

    return hints


def _detect_with_builtwith(url):
    """Use the builtwith library, if available, for broader tech fingerprinting."""
    if not HAS_BUILTWITH or not url:
        return []

    try:
        result = builtwith.parse(url)
    except Exception as e:
        logger.warning("builtwith failed for %s: %s", url, e)
        return []

    techs = []
    for category, names in result.items():
        for name in names:
            techs.append(f"{name} ({category})")
    return techs


def run(domain):
    headers, final_url = _fetch_headers(domain)

    technologies = []
    technologies.extend(_detect_from_headers(headers))
    technologies.extend(_detect_with_builtwith(final_url or domain))

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for tech in technologies:
        if tech not in seen:
            seen.add(tech)
            deduped.append(tech)

    status = "ok" if (headers or deduped) else "no_response"

    return {
        "technologies": deduped,
        "headers": headers,
        "status": status,
    }