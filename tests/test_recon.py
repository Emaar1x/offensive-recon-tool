"""
test_recon.py - Full test suite for the Offensive Recon Tool (Task 6).

Covers:
    - CLI smoke tests via subprocess (argument parsing, help, error paths)
    - Module interface contracts (every module exposes run(...) -> dict
      with the keys recon.py / report.py depend on)
    - Unit tests for pure logic (port-spec parsing, banner/version
      extraction, domain-age categorization, SPF/risk scoring, etc.)
    - Report generation (json / txt / html) against a realistic sample
      results dict

All network- and socket-dependent calls (WHOIS, DNS, HTTP, TCP connects)
are mocked so the suite runs fully offline, deterministically, and fast.

Run with:  python -m pytest tests/ -v
"""

import json
import logging
import os
import socket
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

RECON_PY = os.path.join(PROJECT_ROOT, "recon.py")

from modules import whois_dns, subdomains, portscan, techdetect, report

# Helpers

def run_cli(*args, timeout=30):
    """Run `python recon.py <args>` and capture the result."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, RECON_PY, *args],
        capture_output=True, text=True, timeout=timeout,
        env=env,
        encoding="utf-8",
    )

SAMPLE_RESULTS = {
    "whois_dns": {
        "domain": "example.com",
        "resolved_ip": "93.184.216.34",
        "whois": {
            "registrar": "RESERVED-Internet Assigned Numbers Authority",
            "creation_date": "1995-08-14 04:00:00",
            "expiration_date": "2030-08-13 04:00:00",
        },
        "dns": {"A": ["93.184.216.34"], "MX": [], "TXT": [], "NS": ["a.iana-servers.net"]},
        "risk_score": 12,
        "risk_level": "Low",
        "risk_explanation": "Risk is Low (12/100).",
        "security_findings": [
            {"finding": "No SPF record found.", "severity": "MEDIUM", "category": "EMAIL"}
        ],
    },
    "subdomains": {
        "domain": "example.com",
        "total_found": 2,
        "subdomains": ["www.example.com", "mail.example.com"],
        "ip_resolution": {"www.example.com": "93.184.216.34", "mail.example.com": "unresolved"},
    },
    "portscan": {
        "target_ip": "93.184.216.34",
        "ports_scanned": 100,
        "total_open": 1,
        "services": [{"port": 443, "state": "open", "service": "HTTPS", "version": None}],
    },
    "techdetect": {
        "technologies": ["nginx"],
        "headers": {"Server": "nginx"},
    },
}

# 1. CLI smoke tests

class TestCLISmoke:

    def test_help_flag_exits_zero(self):
        result = run_cli("--help")
        assert result.returncode == 0
        assert "Offensive Recon Tool" in result.stdout

    def test_help_ports_standalone_no_domain_needed(self):
        """--help-ports should work without a domain and without hitting the network."""
        result = run_cli("--help-ports")
        assert result.returncode == 0
        assert "PORT SCAN MODULE - HELP" in result.stdout

    def test_missing_domain_fails(self):
        result = run_cli()
        assert result.returncode != 0
        assert "domain is required" in result.stdout

    def test_no_module_selected_fails(self):
        result = run_cli("example.com")
        assert result.returncode != 0
        assert "No module selected" in result.stdout

    def test_invalid_output_format_rejected_by_argparse(self):
        result = run_cli("example.com", "--whois", "-o", "xml")
        assert result.returncode != 0
        assert "invalid choice" in result.stderr.lower()

    def test_unknown_flag_rejected(self):
        result = run_cli("example.com", "--bogus-flag")
        assert result.returncode != 0

# 2. Module interface contracts
#    Every module must expose run(domain) -> dict (portscan also accepts
#    an optional port_spec, per recon.py's run_module()).

class TestModuleInterfaceContracts:

    @pytest.mark.parametrize("module", [whois_dns, subdomains, portscan, techdetect])
    def test_module_exposes_callable_run(self, module):
        assert hasattr(module, "run"), f"{module.__name__} must expose run()"
        assert callable(module.run)

    def test_report_exposes_generate(self):
        assert hasattr(report, "generate")
        assert callable(report.generate)

    def test_whois_dns_run_returns_expected_top_level_keys(self):
        with patch.object(whois_dns, "_get_whois_info", return_value={"error": "no network"}), \
             patch.object(whois_dns, "_get_dns_records", return_value={
                 "A": [], "MX": [], "TXT": [], "NS": [], "errors": {"A": "no network"}
             }), \
             patch.object(whois_dns, "_resolve_ip", return_value=None):
            result = whois_dns.run("example.com")
        for key in ("domain", "timestamp", "resolved_ip", "whois", "dns", "status",
                    "risk_score", "risk_level", "security_findings", "recommendations"):
            assert key in result

    def test_subdomains_run_returns_expected_keys(self):
        with patch.object(subdomains, "query_hackertarget", return_value=set()), \
             patch.object(subdomains, "query_crtsh", return_value=set()), \
             patch.object(subdomains, "query_otx", return_value=set()):
            result = subdomains.run("example.com")
        for key in ("domain", "total_found", "sources", "subdomains", "ip_resolution"):
            assert key in result

    def test_portscan_run_returns_expected_keys(self):
        with patch.object(portscan, "scan_port", return_value=None):
            result = portscan.run("93.184.216.34", "22")
        for key in ("target", "target_ip", "open_ports", "total_open", "services",
                    "ports_scanned", "status"):
            assert key in result

    def test_techdetect_run_returns_expected_keys(self):
        with patch.object(techdetect, "_fetch_headers", return_value=({"Server": "nginx"}, "https://example.com")):
            result = techdetect.run("example.com")
        for key in ("technologies", "headers", "status"):
            assert key in result

    def test_report_generate_returns_string_path_or_empty(self):
        path = report.generate("example.com", SAMPLE_RESULTS, fmt="json")
        try:
            assert isinstance(path, str) and path
        finally:
            if path and os.path.exists(path):
                os.remove(path)

# 3. recon.py dispatch: each CLI flag should invoke the right module's run(),
#    without hitting the real network.

class TestReconDispatch:

    @pytest.mark.parametrize("flag,module_name", [
        ("--whois", "whois_dns"),
        ("--dns", "whois_dns"),
        ("--subdomains", "subdomains"),
        ("--ports", "portscan"),
        ("--tech", "techdetect"),
    ])
    def test_run_module_dispatches_to_correct_module(self, flag, module_name):
        """
        Exercises recon.py's run_module() dispatch logic directly (not via
        subprocess) so we can mock out each module's run() and assert it
        was called for the right flag - the CLI-level subprocess tests
        above already confirm argument parsing / exit codes separately.
        """
        import recon as recon_module

        target_module = getattr(recon_module, module_name)
        with patch.object(target_module, "run", return_value={"status": "ok"}) as mock_run:
            results = {}
            recon_module.run_module(module_name, target_module, "example.com", results,
                                     port_spec="top100")
            assert mock_run.called
            assert results[module_name] == {"status": "ok"}

    def test_run_module_catches_exceptions_and_records_error(self):
        import recon as recon_module

        with patch.object(whois_dns, "run", side_effect=RuntimeError("boom")):
            results = {}
            recon_module.run_module("whois_dns", whois_dns, "example.com", results)
            assert "error" in results["whois_dns"]
            assert "boom" in results["whois_dns"]["error"]

# 4. Port scanning module - port-spec parsing 

class TestPortSpecParsing:

    def test_default_and_top100_return_same_list(self):
        assert portscan.parse_port_spec("default") == portscan.TOP_100_PORTS
        assert portscan.parse_port_spec("top100") == portscan.TOP_100_PORTS

    def test_top1000_returns_1_to_1000(self):
        result = portscan.parse_port_spec("top1000")
        assert result == list(range(1, 1001))

    def test_comma_separated_list(self):
        result = portscan.parse_port_spec("80,443,8080")
        assert result == [80, 443, 8080]

    def test_range_spec(self):
        result = portscan.parse_port_spec("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_reversed_range_is_normalized(self):
        result = portscan.parse_port_spec("5-1")
        assert result == [1, 2, 3, 4, 5]

    def test_mixed_range_and_list(self):
        result = portscan.parse_port_spec("1-3,443,10-12")
        assert result == [1, 2, 3, 10, 11, 12, 443]

    def test_single_int_port(self):
        assert portscan.parse_port_spec(22) == [22]

    def test_list_passthrough(self):
        assert portscan.parse_port_spec([21, 22, 23]) == [21, 22, 23]

    def test_invalid_entries_are_skipped_not_raised(self):
        # "abc" isn't a valid port and shouldn't crash parsing
        result = portscan.parse_port_spec("80,abc,443")
        assert result == [80, 443]

    def test_unknown_type_falls_back_to_top100(self):
        assert portscan.parse_port_spec(None) == portscan.TOP_100_PORTS

class TestVersionExtraction:

    def test_extracts_openssh_version(self):
        version = portscan.extract_version("SSH", "SSH-2.0-OpenSSH_8.9p1")
        assert version == "8.9p1"

    def test_extracts_nginx_version(self):
        version = portscan.extract_version("HTTP Server", "Server: nginx/1.18.0")
        assert version == "1.18.0"

    def test_no_banner_returns_none(self):
        assert portscan.extract_version("HTTP", None) is None

    def test_unmatched_banner_returns_none_or_generic(self):
        # No known signature and no numeric pattern present
        assert portscan.extract_version("Unknown", "hello there") is None

class TestPortscanRun:

    def test_run_resolves_domain_and_scans_ports(self):
        with patch("socket.gethostbyname", return_value="93.184.216.34"), \
             patch.object(portscan, "scan_port") as mock_scan:
            mock_scan.side_effect = lambda target, port: (
                {"port": 443, "service": "HTTPS", "version": None, "banner": None, "state": "open"}
                if port == 443 else None
            )
            result = portscan.run("example.com", "443,8443")

        assert result["status"] == "success"
        assert result["target_ip"] == "93.184.216.34"
        assert result["open_ports"] == [443]
        assert result["total_open"] == 1

    def test_run_reports_error_on_unresolvable_domain(self):
        with patch("socket.gethostbyname", side_effect=socket.gaierror("no such host")):
            result = portscan.run("not-a-real-domain.invalid", "22")
        assert result["status"] == "error"
        assert result["target_ip"] is None
        assert "error" in result

    def test_run_no_open_ports_status(self):
        with patch("socket.gethostbyname", return_value="93.184.216.34"), \
             patch.object(portscan, "scan_port", return_value=None):
            result = portscan.run("example.com", "9-9")
        assert result["status"] == "no_open_ports"
        assert result["total_open"] == 0

# 5. Subdomain enumeration module

class TestSubdomainsModule:

    def test_query_hackertarget_parses_csv_response(self):
        mock_resp = MagicMock(status_code=200, text="www.example.com,1.2.3.4\nmail.example.com,1.2.3.5")
        with patch.object(subdomains.requests, "get", return_value=mock_resp):
            result = subdomains.query_hackertarget("example.com")
        assert result == {"www.example.com", "mail.example.com"}

    def test_query_hackertarget_handles_rate_limit_error_text(self):
        mock_resp = MagicMock(status_code=200, text="error check your usage limits")
        with patch.object(subdomains.requests, "get", return_value=mock_resp):
            result = subdomains.query_hackertarget("example.com")
        assert result == set()

    def test_query_hackertarget_handles_request_exception(self):
        with patch.object(subdomains.requests, "get", side_effect=subdomains.requests.exceptions.Timeout()):
            result = subdomains.query_hackertarget("example.com")
        assert result == set()

    def test_query_crtsh_parses_json_and_dedupes_wildcards(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.text = json.dumps([
            {"name_value": "*.example.com\nwww.example.com"},
            {"name_value": "api.example.com"},
        ])
        with patch.object(subdomains.requests, "get", return_value=mock_resp):
            result = subdomains.query_crtsh("example.com")
        assert result == {"example.com", "www.example.com", "api.example.com"}

    def test_query_otx_respects_rate_limit(self):
        mock_resp = MagicMock(status_code=429)
        with patch.object(subdomains.requests, "get", return_value=mock_resp):
            result = subdomains.query_otx("example.com")
        assert result == set()

    def test_resolve_ip_wildcard_shortcircuit(self):
        assert subdomains.resolve_ip("*.example.com") == "wildcard"

    def test_resolve_ip_unresolvable_returns_unresolved(self):
        with patch("socket.gethostbyname", side_effect=socket.gaierror()):
            assert subdomains.resolve_ip("doesnotexist.example.com") == "unresolved"

    def test_run_merges_all_sources_and_resolves_ips(self):
        with patch.object(subdomains, "query_hackertarget", return_value={"www.example.com"}), \
             patch.object(subdomains, "query_crtsh", return_value={"api.example.com"}), \
             patch.object(subdomains, "query_otx", return_value=set()), \
             patch.object(subdomains, "resolve_ip", return_value="1.2.3.4"):
            result = subdomains.run("example.com")

        assert result["total_found"] == 2
        assert result["subdomains"] == ["api.example.com", "www.example.com"]
        assert result["sources"]["hackertarget"] == ["www.example.com"]
        assert result["ip_resolution"]["api.example.com"] == "1.2.3.4"

# 6. Technology detection module

class TestTechdetectModule:

    def test_detect_from_headers_finds_server_and_powered_by(self):
        headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1"}
        hints = techdetect._detect_from_headers(headers)
        assert "nginx/1.18.0" in hints
        assert "PHP/8.1" in hints

    def test_detect_from_headers_flags_cloudflare(self):
        headers = {"CF-RAY": "abc123-DFW"}
        hints = techdetect._detect_from_headers(headers)
        assert "Cloudflare" in hints

    def test_detect_from_headers_empty_when_no_signals(self):
        assert techdetect._detect_from_headers({}) == []

    def test_run_dedupes_and_merges_technologies(self):
        with patch.object(techdetect, "_fetch_headers", return_value=({"Server": "nginx"}, "https://example.com")), \
             patch.object(techdetect, "_detect_with_builtwith", return_value=["nginx", "React (javascript-frameworks)"]):
            result = techdetect.run("example.com")

        assert result["status"] == "ok"
        # "nginx" appears from both header detection and builtwith - must be deduped
        assert result["technologies"].count("nginx") == 1
        assert "React (javascript-frameworks)" in result["technologies"]

    def test_run_reports_no_response_when_everything_fails(self):
        with patch.object(techdetect, "_fetch_headers", return_value=({}, None)), \
             patch.object(techdetect, "_detect_with_builtwith", return_value=[]):
            result = techdetect.run("unreachable.invalid")
        assert result["status"] == "no_response"
        assert result["technologies"] == []

# 7. WHOIS / DNS module - pure helper logic

class TestWhoisDnsHelpers:

    @pytest.mark.parametrize("age_days,expected", [
        (None, "Unknown"),
        (10, "0-30 days"),
        (100, "31-180 days"),
        (300, "181-365 days"),
        (900, "1-5 years"),
        (3000, "5-10 years"),
        (5000, "10+ years"),
    ])
    def test_categorize_domain_age(self, age_days, expected):
        assert whois_dns._categorize_domain_age(age_days) == expected

    def test_parse_whois_date_common_format(self):
        result = whois_dns._parse_whois_date("2020-01-15 00:00:00")
        assert result is not None
        assert result.year == 2020 and result.month == 1 and result.day == 15

    def test_parse_whois_date_returns_none_for_garbage(self):
        assert whois_dns._parse_whois_date("not-a-date") is None
        assert whois_dns._parse_whois_date(None) is None
        assert whois_dns._parse_whois_date("None") is None

    def test_check_spf_detects_hard_fail(self):
        result = whois_dns._check_spf(["v=spf1 include:_spf.example.com -all"])
        assert result["status"] == "Present"
        assert result["qualifier"] == "-all"

    def test_check_spf_missing(self):
        result = whois_dns._check_spf(["some other txt record"])
        assert result["status"] == "Missing"

    def test_analyze_domain_handles_whois_error(self):
        analysis = whois_dns._analyze_domain({"error": "privacy protected"})
        assert analysis["registration_status"] == "Unknown (WHOIS lookup failed)"
        assert analysis["age_days"] is None

    def test_analyze_domain_known_registrar_detected(self):
        analysis = whois_dns._analyze_domain({
            "registrar": "GoDaddy.com, LLC",
            "creation_date": "2020-01-01 00:00:00",
            "expiration_date": "2030-01-01 00:00:00",
        })
        assert analysis["registrar_known"] is True

    def test_analyze_dns_detects_cloudflare_provider(self):
        dns_info = {"A": ["1.2.3.4"], "AAAA": [], "CNAME": [], "NS": ["ns1.cloudflare.com"],
                    "MX": [], "ttls": {"A": 300}, "errors": {}}
        analysis = whois_dns._analyze_dns(dns_info)
        assert "Cloudflare" in analysis["dns_providers"]

    def test_analyze_dns_flags_no_dns_presence(self):
        dns_info = {"A": [], "AAAA": [], "CNAME": [], "NS": [], "MX": [], "ttls": {}, "errors": {}}
        analysis = whois_dns._analyze_dns(dns_info)
        assert analysis["no_dns_presence"] is True

    def test_calculate_risk_new_domain_no_email_security_is_high_risk(self):
        analysis = {
            "domain_analysis": {
                "age_category": "0-30 days", "expiring_soon": False,
                "days_until_expiration": None, "registrar_known": False,
                "registration_status": "Registered",
            },
            "dns_analysis": {"dns_providers": ["Unknown / custom"], "no_dns_presence": False},
            "email_security": {
                "spf": {"status": "Missing"}, "dmarc": {"status": "Missing"},
                "dkim": {"status": "Undetermined"},
            },
        }
        whois_info = {"registrar": "Sketchy Registrar"}
        dns_info = {"errors": {}}
        score, level, breakdown = whois_dns._calculate_risk(analysis, whois_info, dns_info)
        assert score > 50
        assert level in ("High", "Critical")
        assert len(breakdown) > 0

    def test_calculate_risk_established_domain_is_low_risk(self):
        analysis = {
            "domain_analysis": {
                "age_category": "10+ years", "expiring_soon": False,
                "days_until_expiration": 900, "registrar_known": True,
                "registration_status": "Registered",
            },
            "dns_analysis": {"dns_providers": ["Cloudflare"], "no_dns_presence": False},
            "email_security": {
                "spf": {"status": "Present", "qualifier": "-all"},
                "dmarc": {"status": "Present"},
                "dkim": {"status": "Present"},
            },
        }
        whois_info = {"registrar": "Cloudflare"}
        dns_info = {"errors": {}}
        score, level, breakdown = whois_dns._calculate_risk(analysis, whois_info, dns_info)
        assert score <= 20
        assert level == "Low"

    def test_explain_risk_score_no_factors(self):
        text = whois_dns._explain_risk_score(0, "Low", [])
        assert "Low" in text and "No significant risk factors" in text

    def test_explain_risk_score_lists_top_factors(self):
        breakdown = [{"factor": "A", "points": 30}, {"factor": "B", "points": 20},
                     {"factor": "C", "points": 10}, {"factor": "D", "points": 5}]
        text = whois_dns._explain_risk_score(65, "High", breakdown)
        assert "A (+30)" in text
        assert "1 more minor factor" in text

class TestWhoisDnsRun:

    def test_run_status_success_when_both_whois_and_dns_ok(self):
        with patch.object(whois_dns, "_get_whois_info", return_value={
                "registrar": "GoDaddy.com, LLC", "creation_date": "2020-01-01 00:00:00",
                "expiration_date": "2030-01-01 00:00:00", "name_servers": ["ns1.godaddy.com"],
             }), \
             patch.object(whois_dns, "_get_dns_records", return_value={
                "A": ["1.2.3.4"], "AAAA": [], "CNAME": [], "MX": [], "TXT": [], "NS": [],
                "ttls": {}, "dnssec_enabled": None, "errors": {},
             }), \
             patch.object(whois_dns, "_resolve_ip", return_value="1.2.3.4"), \
             patch.object(whois_dns, "_check_dmarc", return_value={"status": "Missing", "record": None}), \
             patch.object(whois_dns, "_check_dkim", return_value={"status": "Undetermined", "selector_found": None}):
            result = whois_dns.run("example.com")

        assert result["status"] == "success"
        assert result["resolved_ip"] == "1.2.3.4"
        assert isinstance(result["risk_score"], int)

    def test_run_status_error_when_both_whois_and_dns_fail(self):
        with patch.object(whois_dns, "_get_whois_info", return_value={"error": "no network"}), \
             patch.object(whois_dns, "_get_dns_records", return_value={
                "A": [], "MX": [], "TXT": [], "NS": [], "errors": {"A": "no network"},
             }), \
             patch.object(whois_dns, "_resolve_ip", return_value=None):
            result = whois_dns.run("example.com")
        assert result["status"] == "error"

    def test_run_analysis_failure_degrades_gracefully(self):
        """If the analysis layer throws, run() must still return the core fields."""
        with patch.object(whois_dns, "_get_whois_info", return_value={"registrar": "X"}), \
             patch.object(whois_dns, "_get_dns_records", return_value={
                "A": ["1.2.3.4"], "MX": [], "TXT": [], "NS": [], "errors": {},
             }), \
             patch.object(whois_dns, "_resolve_ip", return_value="1.2.3.4"), \
             patch.object(whois_dns, "_build_analysis", side_effect=RuntimeError("boom")):
            result = whois_dns.run("example.com")

        assert result["risk_level"] == "Unknown"
        assert result["recommendations"] == []
        assert "domain" in result and "whois" in result and "dns" in result

# 8. Report generation module

class TestReportGeneration:

    def _cleanup(self, path):
        if path and os.path.exists(path):
            os.remove(path)

    def test_generate_json_report_contains_all_modules(self):
        path = report.generate("example.com", SAMPLE_RESULTS, fmt="json")
        try:
            assert path.endswith(".json") and os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert data["domain"] == "example.com"
            for module in SAMPLE_RESULTS:
                assert module in data["results"]
        finally:
            self._cleanup(path)

    def test_generate_txt_report_contains_key_sections(self):
        path = report.generate("example.com", SAMPLE_RESULTS, fmt="txt")
        try:
            assert path.endswith(".txt") and os.path.exists(path)
            with open(path) as f:
                content = f.read()
            assert "MODULE: WHOIS & DNS" in content
            assert "MODULE: Subdomains" in content
            assert "MODULE: Port Scan" in content
            assert "MODULE: Technology Detection" in content
            assert "example.com" in content
        finally:
            self._cleanup(path)

    def test_generate_html_report_is_valid_and_contains_domain(self):
        path = report.generate("example.com", SAMPLE_RESULTS, fmt="html")
        try:
            assert path.endswith(".html") and os.path.exists(path)
            with open(path) as f:
                content = f.read()
            assert "<html" in content.lower()
            assert "example.com" in content
        finally:
            self._cleanup(path)

    def test_generate_unknown_format_falls_back_to_json(self):
        path = report.generate("example.com", SAMPLE_RESULTS, fmt="pdf")
        try:
            assert path.endswith(".json")
        finally:
            self._cleanup(path)

    def test_generate_handles_module_level_errors_in_results(self):
        broken_results = {"whois_dns": {"error": "network unreachable"}}
        for fmt in ("json", "txt", "html"):
            path = report.generate("example.com", broken_results, fmt=fmt)
            try:
                assert os.path.exists(path)
            finally:
                self._cleanup(path)

    def test_generate_returns_empty_string_on_write_failure(self):
        with patch("builtins.open", side_effect=OSError("disk full")):
            path = report.generate("example.com", SAMPLE_RESULTS, fmt="json")
        assert path == ""

# 9. Logging setup (recon.py)

class TestLoggingSetup:

    def test_setup_logging_creates_log_file(self, tmp_path):
        import recon as recon_module

        with patch.object(recon_module, "LOGS_DIR", str(tmp_path)):
            recon_module.setup_logging(verbosity=0)
            # force a fresh basicConfig on the next test run
            for h in logging.root.handlers[:]:
                logging.root.removeHandler(h)

        log_files = list(tmp_path.glob("recon_*.log"))
        assert len(log_files) == 1

    @pytest.mark.parametrize("verbosity,expected_level", [
        (0, logging.WARNING),
        (1, logging.INFO),
        (2, logging.DEBUG),
    ])
    def test_setup_logging_verbosity_maps_to_level(self, tmp_path, verbosity, expected_level):
        """
        Checks the level setup_logging() passes to logging.basicConfig().
        We mock basicConfig directly rather than inspecting logging.root
        afterwards, since pytest's own log-capturing plugin installs a
        handler on the root logger, which makes basicConfig() a no-op
        (it only configures when no handlers are present yet) and would
        make this test order-dependent instead of a true unit test.
        """
        import recon as recon_module

        with patch.object(recon_module, "LOGS_DIR", str(tmp_path)), \
             patch.object(recon_module.logging, "basicConfig") as mock_basic_config:
            recon_module.setup_logging(verbosity=verbosity)
            assert mock_basic_config.call_args.kwargs["level"] == expected_level

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))