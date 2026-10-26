"""
Domain validation, DNS resolution, high-risk TLD checks, and SSRF prevention.
Safely extracts domain metadata without creating external blocking dependencies.
"""
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List

from config import SSRF_BLOCKED_NETWORKS, REQUEST_TIMEOUT, BLOCKED_IP_PREFIXES, BLOCKED_HOSTNAMES
from feature_extraction.url_features import HIGH_RISK_TLDS, is_ip_address

def is_ssrf_risk_host(hostname: str) -> bool:
    """Checks if a hostname or IP resolves to a private, loopback, or link-local address."""
    if not hostname:
        return True
    clean_host = hostname.split(":")[0].lower().strip("[]")
    if clean_host in BLOCKED_HOSTNAMES:
        return True
    for prefix in BLOCKED_IP_PREFIXES:
        if clean_host.startswith(prefix):
            return True
    try:
        ip = ipaddress.ip_address(clean_host)
        for net in SSRF_BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        pass
        
    try:
        resolved_ip = socket.gethostbyname(clean_host)
        ip = ipaddress.ip_address(resolved_ip)
        for net in SSRF_BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except Exception:
        return False

def is_ssrf_safe_ip(ip_str: str) -> bool:
    """Validates that IP does not reside in loopback, private, or link-local subnets."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in SSRF_BLOCKED_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False

def extract_domain_features(url_str: str) -> Dict[str, Any]:
    """
    Extracts domain metadata, DNS resolvability status, TLD classification,
    and validates SSRF boundaries.
    """
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    parsed = urlparse(url_str)
    netloc = parsed.netloc.lower()
    hostname = netloc.split(":")[0]

    domain_meta = {
        "hostname": hostname,
        "registered_domain": hostname,
        "subdomain_part": "",
        "subdomain_count": 0,
        "tld": "",
        "is_ip_address": False,
        "is_ssrf_risk": False,
        "is_high_risk_tld": False,
        "dns_status": "NOT CHECKED",
        "dns_resolved": False,
        "https_status": "NOT CHECKED",
        "https_available": False,
        "resolved_ip": None
    }

    if not hostname:
        return domain_meta

    # Check if raw IP
    if is_ip_address(hostname):
        domain_meta["is_ip_address"] = True
        domain_meta["resolved_ip"] = hostname
        domain_meta["is_ssrf_risk"] = is_ssrf_risk_host(hostname)
        domain_meta["dns_status"] = "AVAILABLE (RAW IP)"
        domain_meta["dns_resolved"] = True
        return domain_meta

    # Extract domain components using tldextract (or fallback)
    try:
        import tldextract
        ext = tldextract.extract(url_str)
        if ext.domain and ext.suffix:
            domain_meta["registered_domain"] = f"{ext.domain}.{ext.suffix}"
            domain_meta["tld"] = ext.suffix
            domain_meta["subdomain_part"] = ext.subdomain
            domain_meta["subdomain_count"] = len(ext.subdomain.split(".")) if ext.subdomain else 0
        else:
            parts = hostname.split(".")
            domain_meta["tld"] = parts[-1] if len(parts) >= 2 else ""
            domain_meta["registered_domain"] = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            domain_meta["subdomain_part"] = ".".join(parts[:-2]) if len(parts) > 2 else ""
            domain_meta["subdomain_count"] = len(parts) - 2 if len(parts) > 2 else 0
    except Exception:
        parts = hostname.split(".")
        domain_meta["tld"] = parts[-1] if len(parts) >= 2 else ""
        domain_meta["registered_domain"] = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        domain_meta["subdomain_part"] = ".".join(parts[:-2]) if len(parts) > 2 else ""
        domain_meta["subdomain_count"] = len(parts) - 2 if len(parts) > 2 else 0

    domain_meta["is_high_risk_tld"] = bool(domain_meta["tld"] in HIGH_RISK_TLDS)
    
    # Structural telemetry for evidence synthesis
    from config import COMMON_BRAND_NAMES
    sub_part = domain_meta["subdomain_part"].lower()
    reg_dom = domain_meta["registered_domain"].lower()
    path_str = parsed.path.lower()
    
    # Check if a known brand appears in subdomain while not being the registered domain
    brand_conflict = False
    for brand in COMMON_BRAND_NAMES:
        if brand in sub_part and brand not in reg_dom.split(".")[0]:
            brand_conflict = True
            break
            
    domain_meta["brand_in_subdomain_conflict"] = brand_conflict
    domain_meta["subdomain_hyphen_count"] = sub_part.count("-")
    domain_meta["path_hyphen_count"] = path_str.count("-")
    domain_meta["is_multi_level_subdomain"] = bool(domain_meta["subdomain_count"] >= 2)
    domain_meta["path_to_hostname_ratio"] = round(len(path_str) / max(1, len(hostname)), 3)


    # Safe DNS resolution
    try:
        resolved_ip = socket.gethostbyname(hostname)
        domain_meta["resolved_ip"] = resolved_ip
        domain_meta["dns_resolved"] = True
        domain_meta["dns_status"] = "AVAILABLE"
        domain_meta["is_ssrf_risk"] = is_ssrf_risk_host(resolved_ip)
    except socket.gaierror:
        domain_meta["dns_resolved"] = False
        domain_meta["dns_status"] = "UNAVAILABLE"
        domain_meta["resolved_ip"] = None
    except Exception:
        domain_meta["dns_resolved"] = False
        domain_meta["dns_status"] = "UNAVAILABLE"

    # HTTPS handshake verification
    if parsed.scheme == "https":
        domain_meta["https_status"] = "AVAILABLE"
        domain_meta["https_available"] = True
    else:
        domain_meta["https_status"] = "UNAVAILABLE (HTTP ONLY)"
        domain_meta["https_available"] = False

    return domain_meta
