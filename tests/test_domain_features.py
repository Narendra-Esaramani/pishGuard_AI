"""
Unit tests for domain feature extraction and SSRF prevention.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.domain_features import (
    is_ssrf_risk_host,
    extract_domain_features
)

def test_ssrf_risk_detection():
    assert is_ssrf_risk_host("localhost") is True
    assert is_ssrf_risk_host("127.0.0.1") is True
    assert is_ssrf_risk_host("192.168.1.1") is True
    assert is_ssrf_risk_host("10.0.0.5") is True
    assert is_ssrf_risk_host("172.16.0.1") is True
    assert is_ssrf_risk_host("example.com") is False

def test_domain_metadata_extraction():
    url = "https://sub1.sub2.example.com/path"
    info = extract_domain_features(url)
    assert info["registered_domain"] == "example.com"
    assert info["subdomain_count"] == 2
    assert info["tld"] == "com"
    assert info["is_ssrf_risk"] is False
