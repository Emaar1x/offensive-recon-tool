"""
report.py - Report generation (Task 5).

Interface:
    generate(domain, results, fmt="json") -> filepath string

Supports three output formats:
    - "json": raw structured dump of all module results.
    - "txt":  plain-text summary, nicely formatted for human reading.
    - "html": a styled, shareable HTML report (uses jinja2 if available).
"""

import json
import logging
import os
from datetime import datetime

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Recon Report - {{ domain }}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 0; padding: 2rem; background: #0f1115; color: #e6e6e6; }
  h1 { color: #7dd3fc; margin-bottom: 0; }
  .subtitle { color: #9ca3af; margin-top: 0.25rem; }
  .module { background: #1a1d24; border: 1px solid #2a2e37; border-radius: 8px; padding: 1.25rem 1.5rem; margin: 1.25rem 0; }
  .module h2 { margin-top: 0; color: #f0abfc; font-size: 1.1rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #2a2e37; padding-bottom: 0.5rem; }
  .status-ok { color: #4ade80; }
  .status-error { color: #f87171; }
  table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; font-size: 0.95rem; }
  th, td { text-align: left; padding: 0.6rem; border-bottom: 1px solid #2a2e37; }
  th { color: #9ca3af; font-weight: 600; background: #21252d; }
  .badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; background: #374151; }
  .badge-HIGH, .badge-CRITICAL { background: #ef4444; color: white; }
  .badge-MEDIUM { background: #f59e0b; color: white; }
  .badge-LOW { background: #3b82f6; color: white; }
  .badge-INFO { background: #4b5563; color: white; }
  ul { line-height: 1.5; }
  pre { background: #0b0d11; padding: 1rem; border-radius: 6px; overflow-x: auto; font-family: monospace; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
  .card { background: #21252d; padding: 1rem; border-radius: 6px; }
  .card h3 { margin-top: 0; color: #93c5fd; font-size: 1rem; }
  footer { margin-top: 2rem; color: #6b7280; font-size: 0.85rem; }
</style>
</head>
<body>
  <h1>Recon Report</h1>
  <p class="subtitle">Target: <strong>{{ domain }}</strong> &middot; Generated {{ generated_at }}</p>

  {% if "whois_dns" in results %}
  {% set w = results["whois_dns"] %}
  <div class="module">
    <h2>WHOIS & DNS</h2>
    {% if w.get("error") %}
       <p class="status-error">Error: {{ w.error }}</p>
    {% else %}
       <div class="grid">
         <div class="card">
           <h3>WHOIS Information</h3>
           <p><strong>Registrar:</strong> {{ w.get('whois', {}).get('registrar', 'N/A') }}</p>
           <p><strong>Created:</strong> {{ w.get('whois', {}).get('creation_date', 'N/A') }}</p>
           <p><strong>Expires:</strong> {{ w.get('whois', {}).get('expiration_date', 'N/A') }}</p>
         </div>
         <div class="card">
           <h3>Risk Analysis</h3>
           <p><strong>Level:</strong> <span class="badge badge-{{ w.get('risk_level', 'UNKNOWN') | upper }}">{{ w.get('risk_level', 'Unknown') }}</span> ({{ w.get('risk_score', 0) }}/100)</p>
           <p>{{ w.get('risk_explanation', '') }}</p>
         </div>
       </div>
       
       <h3 style="margin-top: 1.5rem;">DNS Records</h3>
       <table>
         <tr><th>Type</th><th>Records</th></tr>
         {% for rtype, records in w.get('dns', {}).items() %}
           {% if records and rtype not in ["ttls", "dnssec_enabled", "errors"] %}
           <tr><td>{{ rtype }}</td><td>{{ records | join(", ") }}</td></tr>
           {% endif %}
         {% endfor %}
       </table>

       <h3 style="margin-top: 1.5rem;">Security Findings</h3>
       <table>
         <tr><th>Severity</th><th>Category</th><th>Finding</th></tr>
         {% for f in w.get('security_findings', []) %}
         <tr>
           <td><span class="badge badge-{{ f.get('severity', 'INFO') | upper }}">{{ f.get('severity', 'INFO') }}</span></td>
           <td>{{ f.get('category', '') }}</td>
           <td>{{ f.get('finding', '') }}</td>
         </tr>
         {% endfor %}
       </table>
    {% endif %}
  </div>
  {% endif %}

  {% if "subdomains" in results %}
  {% set s = results["subdomains"] %}
  <div class="module">
    <h2>Subdomains</h2>
    {% if s.get("error") %}
       <p class="status-error">Error: {{ s.error }}</p>
    {% else %}
       <p>Total Found: <strong>{{ s.get('total_found', 0) }}</strong></p>
       {% if s.get('total_found', 0) > 0 %}
       <table>
         <tr><th>Subdomain</th><th>Resolved IP</th></tr>
         {% for sub in s.get('subdomains', []) %}
         <tr>
           <td>{{ sub }}</td>
           <td>{{ s.get('ip_resolution', {}).get(sub, "unknown") }}</td>
         </tr>
         {% endfor %}
       </table>
       {% endif %}
    {% endif %}
  </div>
  {% endif %}

  {% if "portscan" in results %}
  {% set p = results["portscan"] %}
  <div class="module">
    <h2>Port Scan</h2>
    {% if p.get("error") %}
       <p class="status-error">Error: {{ p.error }}</p>
    {% else %}
       <p>Target IP: <strong>{{ p.get('target_ip', 'N/A') }}</strong> &middot; Ports Scanned: {{ p.get('ports_scanned', 0) }} &middot; Open: <strong>{{ p.get('total_open', 0) }}</strong></p>
       {% if p.get('total_open', 0) > 0 %}
       <table>
         <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
         {% for svc in p.get('services', []) %}
         <tr>
           <td>{{ svc.get('port') }}</td>
           <td class="status-ok">{{ svc.get('state') }}</td>
           <td>{{ svc.get('service') }}</td>
           <td>{{ svc.get('version') or "-" }}</td>
         </tr>
         {% endfor %}
       </table>
       {% endif %}
    {% endif %}
  </div>
  {% endif %}

  {% if "techdetect" in results %}
  {% set t = results["techdetect"] %}
  <div class="module">
    <h2>Technology Detection</h2>
    {% if t.get("error") %}
       <p class="status-error">Error: {{ t.error }}</p>
    {% else %}
       <h3>Detected Technologies</h3>
       {% if t.get('technologies') %}
       <ul>
         {% for tech in t.technologies %}
         <li>{{ tech }}</li>
         {% endfor %}
       </ul>
       {% else %}
       <p>None detected.</p>
       {% endif %}

       <h3 style="margin-top: 1.5rem;">HTTP Headers</h3>
       <pre>{% for k, v in t.get('headers', {}).items() %}
{{ k }}: {{ v }}{% endfor %}</pre>
    {% endif %}
  </div>
  {% endif %}

  <footer>Generated by Offensive Recon Tool</footer>
</body>
</html>
"""


def _ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _timestamped_path(domain, ext):
    safe_domain = domain.replace("/", "_").replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recon_{safe_domain}_{ts}.{ext}"
    return os.path.join(REPORTS_DIR, filename)


def _generate_json(domain, results, generated_at):
    path = _timestamped_path(domain, "json")
    payload = {
        "domain": domain,
        "generated_at": generated_at,
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return path


def _generate_txt(domain, results, generated_at):
    path = _timestamped_path(domain, "txt")
    lines = []
    lines.append("=" * 60)
    lines.append("OFFENSIVE RECON TOOL - REPORT")
    lines.append("=" * 60)
    lines.append(f"Target:       {domain}")
    lines.append(f"Generated at: {generated_at}")
    lines.append("")

    if "whois_dns" in results:
        lines.append("-" * 60)
        lines.append("MODULE: WHOIS & DNS")
        lines.append("-" * 60)
        w = results["whois_dns"]
        if "error" in w:
            lines.append(f"[!] Error: {w['error']}")
        else:
            lines.append("[WHOIS Information]")
            lines.append(f"Registrar: {w.get('whois', {}).get('registrar', 'N/A')}")
            lines.append(f"Created:   {w.get('whois', {}).get('creation_date', 'N/A')}")
            lines.append(f"Expires:   {w.get('whois', {}).get('expiration_date', 'N/A')}")
            lines.append("")
            lines.append("[Risk Analysis]")
            lines.append(f"Level: {w.get('risk_level', 'Unknown')} ({w.get('risk_score', 0)}/100)")
            lines.append(w.get("risk_explanation", ""))
            lines.append("")
            lines.append("[DNS Records]")
            dns = w.get("dns", {})
            for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
                recs = dns.get(rtype, [])
                if recs:
                    lines.append(f"{rtype}: {', '.join(str(r) for r in recs)}")
            lines.append("")
            lines.append("[Security Findings]")
            for f in w.get("security_findings", []):
                lines.append(f"- [{f.get('severity', 'INFO')}] {f.get('finding', '')} ({f.get('category', '')})")
        lines.append("")

    if "subdomains" in results:
        lines.append("-" * 60)
        lines.append("MODULE: Subdomains")
        lines.append("-" * 60)
        s = results["subdomains"]
        if "error" in s:
            lines.append(f"[!] Error: {s['error']}")
        else:
            lines.append(f"Total Found: {s.get('total_found', 0)}")
            for sub in s.get("subdomains", []):
                ip = s.get("ip_resolution", {}).get(sub, "unknown")
                lines.append(f"  {sub} -> {ip}")
        lines.append("")

    if "portscan" in results:
        lines.append("-" * 60)
        lines.append("MODULE: Port Scan")
        lines.append("-" * 60)
        p = results["portscan"]
        if "error" in p:
            lines.append(f"[!] Error: {p['error']}")
        else:
            lines.append(f"Target IP: {p.get('target_ip', 'N/A')}")
            lines.append(f"Total Open Ports: {p.get('total_open', 0)}")
            lines.append("")
            lines.append(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<15}{'VERSION'}")
            for svc in p.get("services", []):
                ver = svc.get("version") or "-"
                lines.append(f"{str(svc.get('port')):<8}{svc.get('state'):<8}{svc.get('service'):<15}{ver}")
        lines.append("")

    if "techdetect" in results:
        lines.append("-" * 60)
        lines.append("MODULE: Technology Detection")
        lines.append("-" * 60)
        t = results["techdetect"]
        if "error" in t:
            lines.append(f"[!] Error: {t['error']}")
        else:
            lines.append("[Detected Technologies]")
            techs = t.get("technologies", [])
            if techs:
                for tech in techs:
                    lines.append(f"- {tech}")
            else:
                lines.append("None detected.")
            lines.append("")
            lines.append("[HTTP Headers]")
            for k, v in t.get("headers", {}).items():
                lines.append(f"{k}: {v}")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def _generate_html(domain, results, generated_at):
    path = _timestamped_path(domain, "html")

    if HAS_JINJA2:
        template = Template(HTML_TEMPLATE)
        html = template.render(domain=domain, results=results, generated_at=generated_at)
    else:
        logger.warning("jinja2 not installed; falling back to basic HTML template.")
        html = f"<html><body><h1>Recon Report for {domain}</h1><pre>{json.dumps(results, indent=2, default=str)}</pre></body></html>"

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def generate(domain, results, fmt="json"):
    _ensure_reports_dir()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    generators = {
        "json": _generate_json,
        "txt": _generate_txt,
        "html": _generate_html,
    }

    generator = generators.get(fmt)
    if generator is None:
        logger.error("Unknown report format '%s', defaulting to json.", fmt)
        generator = _generate_json

    try:
        path = generator(domain, results, generated_at)
        logger.info("Report written to %s", path)
        return path
    except Exception as e:
        logger.error("Failed to generate %s report: %s", fmt, e)
        return ""