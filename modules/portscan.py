"""
portscan.py - Port scanning & banner grabbing (Task 4).

Interface:
    run(domain, port_spec="default") -> dict with scan results

Features:
    - TCP connect scanning with configurable port ranges
    - Service banner grabbing
    - Version extraction from banners
    - SSL/TLS certificate information
    - Custom port specification (ranges, lists, top100, top1000)
    - Multi-threaded scanning
    - Cross-platform (Windows/Linux/Mac)
"""

import logging
import socket
import threading
import queue
import time
import sys
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

logger = logging.getLogger(__name__)

# Platform-specific settings
IS_WINDOWS = sys.platform.startswith('win')
MAX_THREADS = 30 if IS_WINDOWS else 50
SCAN_TIMEOUT = 2
BANNER_TIMEOUT = 3
SCAN_DELAY = 0.05

# Top 100 most common ports
TOP_100_PORTS = [
    1, 3, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 
    37, 42, 43, 49, 50, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 
    90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 
    144, 146, 161, 163, 179, 199, 211, 222, 254, 255, 256, 259, 264, 
    280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 
    443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 
    524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 
    625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 
    711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 790, 800, 801, 
    808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 
    987, 990, 992, 993, 995, 999, 1000
]

# Expanded service mapping
SERVICE_MAP = {
    1: "tcpmux", 3: "compressnet", 7: "echo", 9: "discard", 13: "daytime",
    17: "qotd", 19: "chargen", 20: "ftp-data", 21: "FTP", 22: "SSH",
    23: "Telnet", 24: "priv-mail", 25: "SMTP", 26: "rsftp", 30: "rpc",
    32: "rpc", 33: "dsp", 37: "time", 42: "nameserver", 43: "whois",
    49: "tacacs", 50: "re-mail-ck", 53: "DNS", 70: "gopher", 79: "finger",
    80: "HTTP", 81: "HTTP-Alt", 82: "HTTP-Alt", 83: "HTTP-Alt", 84: "HTTP-Alt",
    85: "HTTP-Alt", 88: "Kerberos", 89: "HTTP-Alt", 90: "HTTP-Alt", 99: "metagram",
    100: "newacct", 106: "pop3pw", 109: "POP2", 110: "POP3", 111: "RPCBind",
    113: "auth", 119: "NNTP", 125: "locus-map", 135: "MSRPC", 139: "NetBIOS-SSN",
    143: "IMAP", 144: "news", 146: "iso-tp0", 161: "SNMP", 163: "cmip-man",
    179: "BGP", 199: "smux", 211: "x25", 222: "rsh-spx", 254: "ciscoweb",
    255: "wins", 256: "fw1", 259: "esro-gen", 264: "bgmp", 280: "http-mgmt",
    301: "hassle", 306: "at-rtp", 311: "asip-webadmin", 340: "zep", 366: "odmr",
    389: "LDAP", 406: "imsp", 407: "timbuktu", 416: "silc", 417: "silc",
    425: "icad", 427: "svrloc", 443: "HTTPS", 444: "snpp", 445: "SMB",
    458: "qft", 464: "kpasswd", 465: "SMTPS", 481: "ph", 497: "retrospect",
    500: "ISAKMP", 512: "exec", 513: "login", 514: "shell", 515: "printer",
    524: "ncp", 541: "uucp", 543: "klogin", 544: "kshell", 545: "ekshell",
    548: "AFP", 554: "RTSP", 555: "dsf", 563: "NNTP-SSL", 587: "SMTP-Submit",
    593: "RPC-HTTP", 616: "gdb", 617: "scp", 625: "openvpn", 631: "CUPS",
    636: "LDAPS", 646: "lmp", 648: "rwhois", 666: "doom", 667: "disclose",
    668: "mecomm", 683: "corba", 687: "omni", 691: "ms-exchange", 700: "afs",
    705: "wais", 711: "cba", 714: "iris", 720: "smqp", 722: "nfs",
    726: "nfs", 749: "kerberos", 765: "webster", 777: "multiling", 783: "spamassassin",
    787: "qsc", 790: "chrp", 800: "mdbs", 801: "device", 808: "ccproxy",
    843: "flash", 873: "rsync", 880: "cgms", 888: "cgi", 898: "sun-manage",
    900: "omg", 901: "samba", 902: "iss", 903: "iss-console", 911: "xact",
    912: "apex-mesh", 981: "sophos", 987: "microsoft", 990: "FTP-SSL",
    992: "Telnet-SSL", 993: "IMAPS", 995: "POP3S", 999: "puprouter", 1000: "cadlock",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5800: "VNC-HTTP", 5901: "VNC-1",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "HTTP-Alt", 27017: "MongoDB", 11211: "Memcached", 6666: "irc",
    6697: "irc-SSL", 8069: "Odoo", 9200: "Elasticsearch", 9300: "Elasticsearch",
    5000: "HTTP-Alt", 5001: "HTTP-Alt", 7001: "WebLogic", 8000: "HTTP-Alt",
    8009: "AJP", 8090: "HTTP-Alt", 8181: "HTTP-Alt", 8282: "HTTP-Alt",
    8880: "HTTP-Alt", 9043: "HTTP-Alt", 9080: "HTTP-Alt", 9090: "HTTP-Alt",
    9443: "HTTPS-Alt", 9999: "HTTP-Alt", 10000: "Webmin", 10001: "HTTP-Alt",
    10002: "HTTP-Alt", 11000: "HTTP-Alt", 11111: "HTTP-Alt", 12000: "HTTP-Alt",
    12345: "NetBus"
}

# Version extraction patterns - prioritize server identification
VERSION_PATTERNS = {
    # Server identification (extract full server string)
    "Vercel": [r"server:\s*([^\r\n]+)", 1],
    "Cloudflare": [r"server:\s*([^\r\n]+)", 1],
    "Fastly": [r"server:\s*([^\r\n]+)", 1],
    "GitHub": [r"server:\s*([^\r\n]+)", 1],
    "GitLab": [r"server:\s*([^\r\n]+)", 1],
    "AmazonS3": [r"server:\s*([^\r\n]+)", 1],
    "Akamai": [r"server:\s*([^\r\n]+)", 1],
    
    # Version extraction for specific services
    "OpenSSH": [r"OpenSSH[_\-](\d+\.\d+[p\d]*)", 1],
    "Apache": [r"Apache[/\-](\d+\.\d+\.\d+)", 1],
    "nginx": [r"nginx[/\-](\d+\.\d+\.\d+)", 1],
    "IIS": [r"Microsoft-IIS[/\-](\d+\.\d+)", 1],
    "MySQL": [r"MySQL[/\-](\d+\.\d+\.\d+)", 1],
    "MariaDB": [r"MariaDB[/\-](\d+\.\d+\.\d+)", 1],
    "PostgreSQL": [r"PostgreSQL[/\-](\d+\.\d+\.\d+)", 1],
    "Tomcat": [r"Tomcat[/\-](\d+\.\d+\.\d+)", 1],
    "Jetty": [r"Jetty[/\-](\d+\.\d+\.\d+)", 1],
    "VNC": [r"RFB\s+(\d+\.\d+)", 1],
    "Redis": [r"Redis[/\-](\d+\.\d+\.\d+)", 1],
    "MongoDB": [r"MongoDB[/\-](\d+\.\d+\.\d+)", 1],
    "OpenVPN": [r"OpenVPN[/\-](\d+\.\d+\.\d+)", 1],
    "Samba": [r"Samba[/\-](\d+\.\d+\.\d+)", 1],
    "ProFTPD": [r"ProFTPD[/\-](\d+\.\d+\.\d+)", 1],
    "vsFTPd": [r"vsFTPd[/\-](\d+\.\d+\.\d+)", 1],
    "Pure-FTPd": [r"Pure-FTPd[/\-](\d+\.\d+\.\d+)", 1],
    "Exim": [r"Exim[/\-](\d+\.\d+\.\d+)", 1],
    "Postfix": [r"Postfix[/\-](\d+\.\d+\.\d+)", 1],
    "Sendmail": [r"Sendmail[/\-](\d+\.\d+\.\d+)", 1],
    "Dovecot": [r"Dovecot[/\-](\d+\.\d+\.\d+)", 1],
    "Courier": [r"Courier[/\-](\d+\.\d+\.\d+)", 1],
    "Zimbra": [r"Zimbra[/\-](\d+\.\d+\.\d+)", 1],
    "Exchange": [r"Microsoft Exchange[/\-](\d+\.\d+\.\d+)", 1],
    "Oracle": [r"Oracle[/\-](\d+\.\d+\.\d+)", 1],
    "MSSQL": [r"Microsoft SQL Server[/\-](\d+\.\d+\.\d+)", 1],
}

# Banner patterns for service identification
BANNER_PATTERNS = {
    b"SSH": "SSH",
    b"OpenSSH": "OpenSSH",
    b"220": "FTP",
    b"HTTP/": "HTTP",
    b"Server:": "HTTP Server",
    b"220 ": "SMTP",
    b"MySQL": "MySQL",
    b"MariaDB": "MariaDB",
    b"PostgreSQL": "PostgreSQL",
    b"nginx": "nginx",
    b"Apache": "Apache",
    b"Microsoft-IIS": "IIS",
    b"Tomcat": "Tomcat",
    b"Jetty": "Jetty",
    b"WebSphere": "WebSphere",
    b"JBoss": "JBoss",
    b"GlassFish": "GlassFish",
    b"VNC": "VNC",
    b"RFB": "VNC",
    b"RDP": "RDP",
    b"Microsoft RDP": "RDP",
    b"MongoDB": "MongoDB",
    b"Redis": "Redis",
    b"Memcached": "Memcached",
    b"OpenVPN": "OpenVPN",
    b"Samba": "Samba",
    b"Elasticsearch": "Elasticsearch",
    b"kibana": "Kibana",
    b"logstash": "Logstash",
    b"rabbitmq": "RabbitMQ",
    b"RabbitMQ": "RabbitMQ",
    b"zookeeper": "ZooKeeper",
    b"ProFTPD": "ProFTPD",
    b"vsFTPd": "vsFTPd",
    b"Pure-FTPd": "Pure-FTPd",
    b"Exim": "Exim",
    b"Postfix": "Postfix",
    b"Sendmail": "Sendmail",
    b"Dovecot": "Dovecot",
    b"Courier": "Courier",
    b"Zimbra": "Zimbra",
    b"Exchange": "Exchange",
    b"Vercel": "Vercel",
    b"Cloudflare": "Cloudflare",
    b"Fastly": "Fastly",
    b"GitHub": "GitHub",
    b"GitLab": "GitLab",
}

# SSL/TLS ports
SSL_PORTS = {443, 465, 563, 636, 989, 990, 992, 993, 994, 995, 8443, 9443}

# Probes for different services
PROBES = {
    21: b"QUIT\r\n",
    22: b"\n",
    25: b"EHLO test\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"QUIT\r\n",
    111: b"\n",
    143: b"A001 LOGOUT\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    445: b"\n",
    587: b"EHLO test\r\n",
    993: b"A001 LOGOUT\r\n",
    995: b"QUIT\r\n",
    3306: b"\x03\x00\x00\x00\x0a",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    9000: b"HEAD / HTTP/1.0\r\n\r\n",
}


def grab_ssl_banner(target: str, port: int) -> Optional[str]:
    """Grab SSL certificate information from HTTPS port."""
    try:
        import ssl
        import socket
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    info = []
                    # Get certificate details
                    if 'subject' in cert:
                        subject = cert['subject']
                        for item in subject:
                            for key, val in item:
                                if key == 'commonName':
                                    info.append(f"CN: {val}")
                                elif key == 'organizationName':
                                    info.append(f"Org: {val}")
                                elif key == 'countryName':
                                    info.append(f"Country: {val}")
                    
                    if 'issuer' in cert:
                        issuer = cert['issuer']
                        for item in issuer:
                            for key, val in item:
                                if key == 'organizationName':
                                    info.append(f"Issuer: {val}")
                    
                    if 'notAfter' in cert:
                        info.append(f"Expires: {cert['notAfter']}")
                    
                    if 'subjectAltName' in cert:
                        san = cert['subjectAltName']
                        domains = [d[1] for d in san if d[0] == 'DNS'][:5]
                        if domains:
                            info.append(f"Domains: {', '.join(domains)}")
                    
                    return "; ".join(info) if info else "SSL/TLS Certificate Present"
        return None
    except Exception as e:
        logger.debug(f"SSL banner grab failed on port {port}: {e}")
        return None


def extract_version(service: str, banner: str) -> Optional[str]:
    """
    Extract version number from service banner.
    Prioritizes server identification over version numbers.
    """
    if not banner:
        return None
    
    # First try to identify the server from banner
    for service_name, pattern_info in VERSION_PATTERNS.items():
        if service_name.lower() in service.lower() or service_name.lower() in banner.lower():
            pattern = pattern_info[0]
            group = pattern_info[1] if len(pattern_info) > 1 else 1
            
            if pattern:
                try:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        version = match.group(group)
                        # If we got a server name, use it as the version
                        if "server:" in pattern.lower() or any(x in service_name.lower() for x in ['vercel', 'cloudflare', 'fastly', 'github', 'gitlab']):
                            logger.debug(f"Identified server: {version}")
                            return version
                        logger.debug(f"Extracted version '{version}' for {service_name}")
                        return version
                except Exception as e:
                    logger.debug(f"Version extraction error for {service_name}: {e}")
    
    # Generic version patterns (fallback)
    generic_patterns = [
        r"v?(\d+\.\d+\.\d+)",      # 1.2.3
        r"v?(\d+\.\d+)",            # 1.2
        r"version[\s:]+([\d.]+)",   # version: 1.2.3
        r"[\s/](\d+\.\d+\.\d+)",    # /1.2.3 or space1.2.3
    ]
    
    for pattern in generic_patterns:
        try:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1)
                # Don't return HTTP/1.0 if we have a server name
                if version not in ["1.0", "1.1", "2.0", "3.0"] or "HTTP" not in banner:
                    logger.debug(f"Extracted generic version '{version}' from banner")
                    return version
        except:
            continue
    
    return None


def parse_port_spec(port_spec: Union[str, int, List[int]]) -> List[int]:
    """Parse various port specifications."""
    if isinstance(port_spec, int):
        return [port_spec]
    
    if isinstance(port_spec, list):
        return port_spec
    
    if isinstance(port_spec, str):
        # Special keywords
        if port_spec.lower() in ["default", "top100"]:
            return TOP_100_PORTS
        
        if port_spec.lower() == "top1000":
            return list(range(1, 1001))
        
        # Check for mixed format: "1-100,200,300-400"
        ports = set()
        parts = port_spec.split(",")
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    if start < end:
                        ports.update(range(start, end + 1))
                    else:
                        ports.update(range(end, start + 1))
                except ValueError:
                    logger.warning(f"Invalid range: {part}")
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    logger.warning(f"Invalid port: {part}")
        
        return sorted(ports)
    
    return TOP_100_PORTS


def scan_port(target: str, port: int) -> Optional[Dict[str, Any]]:
    """Scan a single port and grab banner if open."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SCAN_TIMEOUT)
        
        # Small delay to avoid rate limiting
        time.sleep(SCAN_DELAY)
        
        result = sock.connect_ex((target, port))
        
        if result == 0:
            # For SSL ports, use SSL banner grabbing
            if port in SSL_PORTS:
                banner = grab_ssl_banner(target, port)
                service = SERVICE_MAP.get(port, "Unknown")
                version = None
                
                # Try to identify service from SSL cert
                if banner:
                    if "Vercel" in banner:
                        service = "HTTPS (Vercel)"
                    elif "Cloudflare" in banner:
                        service = "HTTPS (Cloudflare)"
                    elif "Fastly" in banner:
                        service = "HTTPS (Fastly)"
                    elif "GitHub" in banner:
                        service = "HTTPS (GitHub)"
                    elif "GitLab" in banner:
                        service = "HTTPS (GitLab)"
            else:
                banner = grab_banner(sock, port)
                service = SERVICE_MAP.get(port, "Unknown")
                
                # Try to identify service from banner
                if banner:
                    banner_bytes = banner.encode('utf-8', errors='ignore')
                    for pattern, name in BANNER_PATTERNS.items():
                        if pattern in banner_bytes:
                            service = name
                            break
                
                # Extract version
                version = extract_version(service, banner) if banner else None
            
            return {
                "port": port,
                "service": service,
                "version": version,
                "banner": banner,
                "state": "open"
            }
        
        return None
        
    except socket.timeout:
        logger.debug(f"Port {port} scan timeout")
        return None
    except socket.error as e:
        logger.debug(f"Port {port} scan error: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error scanning port {port}: {e}")
        return None
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Grab service banner from open socket."""
    try:
        sock.settimeout(BANNER_TIMEOUT)
        
        # Send probe for certain services
        probe = PROBES.get(port, b"\n")
        try:
            sock.send(probe)
        except:
            pass
        
        # Receive banner
        try:
            banner = sock.recv(1024)
        except:
            return None
        
        if banner:
            try:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
            except:
                try:
                    banner_str = banner.decode('latin-1', errors='ignore').strip()
                except:
                    banner_str = str(banner)[:200]
            
            # Limit banner length
            if len(banner_str) > 200:
                banner_str = banner_str[:200] + "..."
            
            return banner_str if banner_str else None
        
        return None
        
    except:
        return None


def worker(target: str, port_queue: queue.Queue, results: List[Dict], total_ports: int):
    """Worker thread for port scanning."""
    scanned = 0
    last_log_time = time.time()
    start_time = time.time()
    
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break
            
        try:
            result = scan_port(target, port)
            if result:
                results.append(result)
                version_info = f" - Version: {result['version']}" if result.get('version') else ""
                logger.info(f"Port {port} open - Service: {result['service']}{version_info}")
            else:
                logger.debug(f"Port {port} closed")
        except Exception as e:
            logger.error(f"Worker error on port {port}: {e}")
        finally:
            port_queue.task_done()
            scanned += 1
            
            # Log progress every 10 seconds
            current_time = time.time()
            if current_time - last_log_time >= 10:
                elapsed = current_time - start_time
                ports_per_sec = scanned / elapsed if elapsed > 0 else 0
                logger.info(f"Progress: Scanned {scanned}/{total_ports} ports ({ports_per_sec:.1f}/s)")
                last_log_time = current_time


def run(domain: str, port_spec: Union[str, int, List[int]] = "default") -> Dict[str, Any]:
    """Main entry point for port scanning module."""
    logger.info(f"Starting port scan for {domain}")
    
    # Resolve domain to IP if needed
    target_ip = domain
    try:
        socket.inet_aton(domain)
    except socket.error:
        try:
            target_ip = socket.gethostbyname(domain)
            logger.info(f"Resolved {domain} -> {target_ip}")
        except socket.gaierror as e:
            error_msg = f"Failed to resolve domain {domain}: {e}"
            logger.error(error_msg)
            return {
                "target": domain,
                "target_ip": None,
                "open_ports": [],
                "total_open": 0,
                "services": [],
                "scan_duration": 0,
                "ports_scanned": 0,
                "status": "error",
                "error": error_msg,
                "timestamp": datetime.now().isoformat(),
                "platform": "Windows" if IS_WINDOWS else "Unix/Linux"
            }
    
    # Parse port specification
    try:
        port_list = parse_port_spec(port_spec)
        if not port_list:
            logger.warning("Empty port list, using default")
            port_list = TOP_100_PORTS
    except Exception as e:
        logger.error(f"Invalid port specification: {e}")
        port_list = TOP_100_PORTS
    
    total_ports = len(port_list)
    logger.info(f"Scanning {total_ports} ports")
    
    start_time = time.time()
    
    # Create queue with ports to scan
    port_queue = queue.Queue()
    for port in port_list:
        port_queue.put(port)
    
    results = []
    threads = []
    
    # Start worker threads
    thread_count = min(MAX_THREADS, total_ports)
    
    for i in range(thread_count):
        t = threading.Thread(target=worker, args=(target_ip, port_queue, results, total_ports))
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Wait for all threads to complete
    for t in threads:
        try:
            t.join(timeout=120)
        except:
            pass
    
    scan_duration = time.time() - start_time
    
    # Sort results by port number
    results.sort(key=lambda x: x["port"])
    
    open_ports = [r["port"] for r in results]
    
    # Count services with versions
    services_with_version = sum(1 for r in results if r.get('version'))
    
    logger.info(f"Port scan completed in {scan_duration:.2f}s - Found {len(open_ports)} open ports")
    logger.info(f"Version information extracted for {services_with_version} services")
    
    return {
        "target": domain,
        "target_ip": target_ip,
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "services": results,
        "scan_duration": round(scan_duration, 2),
        "ports_scanned": total_ports,
        "port_spec": str(port_spec) if isinstance(port_spec, (str, int)) else "custom_list",
        "services_with_version": services_with_version,
        "status": "success" if results else "no_open_ports",
        "timestamp": datetime.now().isoformat(),
        "platform": "Windows" if IS_WINDOWS else "Unix/Linux"
    }


# For standalone testing
if __name__ == "__main__":
    import json
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    
    if len(sys.argv) < 2:
        print("="*60)
        print("PORT SCAN MODULE - Standalone Testing")
        print("="*60)
        print("\nUsage: python portscan.py <domain> [port-spec]")
        print("\nPort Specifications:")
        print("  default/top100  : Top 100 most common ports")
        print("  top1000         : Ports 1-1000")
        print("  80,443,8080     : Comma-separated list")
        print("  1-1000          : Range")
        print("  1-100,200,300-400 : Mixed range and list")
        print("\nExamples:")
        print("  python portscan.py example.com")
        print("  python portscan.py example.com top1000")
        print("  python portscan.py example.com 80,443,8080")
        print("  python portscan.py example.com 1-100")
        print("  python portscan.py example.com 1-100,443,8000-9000")
        sys.exit(1)
    
    domain = sys.argv[1]
    port_spec = sys.argv[2] if len(sys.argv) > 2 else "default"
    
    print(f"\n[*] Scanning {domain} with port spec: {port_spec}")
    result = run(domain, port_spec)
    
    print("\n" + "="*60)
    print("PORT SCAN RESULTS")
    print("="*60)
    print(json.dumps(result, indent=2, default=str))
    
    # Pretty print services
    if result.get('services'):
        print("\n" + "-"*60)
        print("OPEN PORTS SUMMARY")
        print("-"*60)
        for svc in result['services']:
            version_info = f" (v{svc['version']})" if svc.get('version') else ""
            print(f"  {svc['port']:>5}  {svc['service']:<15}{version_info}")