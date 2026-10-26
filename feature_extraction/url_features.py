"""
Enhanced lexical and syntactic feature extraction from URL strings.
Includes expanded security keyword taxonomy, hyphenated brand-spoofing detection,
and strict numeric feature extraction matching the 48-feature schema.
"""
import re
import math
from typing import Dict, Any, List
from urllib.parse import urlparse

SENSITIVE_KEYWORDS = [
    "secure", "account", "update", "banking", "login", "signin",
    "verify", "verification", "confirm", "confirmation", "auth",
    "portal", "security", "recovery", "wallet", "support", "billing",
    "service", "checkpoint", "alert", "validation", "authenticate",
    "credential", "suspend", "session", "appleid", "office365",
    "microsoft365", "token", "password", "ebayisapi", "webscr"
]

HIGH_RISK_TLDS = {
    "xyz", "top", "online", "club", "work", "site", "vip", "icu",
    "tk", "ml", "ga", "cf", "gq", "buzz", "cam", "monster", "rest", "surf"
}

COMMON_BRAND_NAMES = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "dropbox", "adobe", "yahoo", "ebay",
    "walmart", "twitter", "linkedin", "steam", "whatsapp", "telegram",
    "spotify", "aquent", "docusign", "citibank", "bofa", "metamask",
    "zoom", "fedex", "dhl", "usps", "att", "verizon", "roblox"
]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string to detect randomized/generated tokens."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_ip_address(hostname: str) -> bool:
    """Checks if hostname is an IPv4 or IPv6 address."""
    clean_host = hostname.split(":")[0].strip("[]")
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, clean_host):
        parts = clean_host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    if ":" in clean_host:
        return True
    return False

def extract_url_features(url_str: str) -> Dict[str, float]:
    """
    Extracts all 26 raw URL-derived lexical features plus the 2 URL rule-thresholds.
    Total: 28 pure URL features.
    """
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    parsed = urlparse(url_str)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    hostname = netloc.split(":")[0]
    
    num_dots = float(url_str.count("."))
    
    # Subdomain level
    host_parts = hostname.split(".")
    is_ip = is_ip_address(hostname)
    
    if is_ip or len(host_parts) <= 2:
        subdomain_level = 0.0
    else:
        # e.g., auth.secure.example.com -> 4 parts -> 2 subdomains
        subdomain_level = float(len(host_parts) - 2)

    # Path Level
    clean_path = path.strip("/")
    path_level = float(len(clean_path.split("/"))) if clean_path else 0.0

    url_length = float(len(url_str))
    num_dash = float(url_str.count("-"))
    num_dash_hostname = float(hostname.count("-"))
    at_symbol = 1.0 if "@" in url_str else 0.0
    tilde_symbol = 1.0 if "~" in url_str else 0.0
    num_underscore = float(url_str.count("_"))
    num_percent = float(url_str.count("%"))

    query_components = query.split("&") if query else []
    num_query_components = float(len([q for q in query_components if q]))
    num_ampersand = float(url_str.count("&"))
    num_hash = float(url_str.count("#"))
    num_numeric = float(sum(c.isdigit() for c in url_str))
    no_https = 1.0 if scheme != "https" else 0.0

    # Random String / Entropy
    entropy = calculate_shannon_entropy(hostname + path)
    has_hex = bool(re.search(r"[0-9a-fA-F]{8,}", url_str))
    random_string = 1.0 if (entropy > 3.8 or has_hex) else 0.0

    ip_feature = 1.0 if is_ip else 0.0

    # Domain in Subdomains / Paths
    registered_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 and not is_ip else hostname
    domain_in_subdomains = 0.0
    if subdomain_level > 0:
        subdomain_str = ".".join(host_parts[:-2])
        for brand in COMMON_BRAND_NAMES:
            if brand in subdomain_str:
                domain_in_subdomains = 1.0
                break

    domain_in_paths = 0.0
    path_lower = path.lower()
    for brand in COMMON_BRAND_NAMES:
        if brand in path_lower:
            domain_in_paths = 1.0
            break

    https_in_hostname = 1.0 if ("http" in hostname or "https" in hostname) else 0.0
    hostname_length = float(len(hostname))
    path_length = float(len(path))
    query_length = float(len(query))
    double_slash_in_path = 1.0 if "//" in path else 0.0

    # Sensitive words count
    url_lower = url_str.lower()
    sensitive_word_count = 0
    for word in SENSITIVE_KEYWORDS:
        if word in url_lower:
            sensitive_word_count += 1
    num_sensitive_words = float(min(sensitive_word_count, 3))

    # Embedded brand name & hyphenated brand squatting check
    embedded_brand_name = 0.0
    for brand in COMMON_BRAND_NAMES:
        if brand in url_lower:
            # If brand appears in URL, but the registered domain is NOT exactly the official brand domain
            if not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com") or hostname == brand or hostname == f"www.{brand}.com"):
                embedded_brand_name = 1.0
                break

    # Rule-Threshold derivations
    # SubdomainLevelRT: 1 if <=1, 0 if ==2, -1 if >=3
    if subdomain_level <= 1:
        subdomain_level_rt = 1.0
    elif subdomain_level == 2:
        subdomain_level_rt = 0.0
    else:
        subdomain_level_rt = -1.0

    # UrlLengthRT: 1 if <=54, 0 if 55-75, -1 if >75
    if url_length <= 54:
        url_length_rt = 1.0
    elif 54 < url_length <= 75:
        url_length_rt = 0.0
    else:
        url_length_rt = -1.0

    return {
        "NumDots": num_dots,
        "SubdomainLevel": subdomain_level,
        "PathLevel": path_level,
        "UrlLength": url_length,
        "NumDash": num_dash,
        "NumDashInHostname": num_dash_hostname,
        "AtSymbol": at_symbol,
        "TildeSymbol": tilde_symbol,
        "NumUnderscore": num_underscore,
        "NumPercent": num_percent,
        "NumQueryComponents": num_query_components,
        "NumAmpersand": num_ampersand,
        "NumHash": num_hash,
        "NumNumericChars": num_numeric,
        "NoHttps": no_https,
        "RandomString": random_string,
        "IpAddress": ip_feature,
        "DomainInSubdomains": domain_in_subdomains,
        "DomainInPaths": domain_in_paths,
        "HttpsInHostname": https_in_hostname,
        "HostnameLength": hostname_length,
        "PathLength": path_length,
        "QueryLength": query_length,
        "DoubleSlashInPath": double_slash_in_path,
        "NumSensitiveWords": num_sensitive_words,
        "EmbeddedBrandName": embedded_brand_name,
        "SubdomainLevelRT": subdomain_level_rt,
        "UrlLengthRT": url_length_rt
    }
