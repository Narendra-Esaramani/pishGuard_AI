"""
Unit tests for URL feature extraction and schema alignment.
"""
import sys
from pathlib import Path
import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.url_features import extract_url_features, is_ip_address
from feature_extraction.feature_schema import FEATURE_NAMES, validate_and_order_features
from feature_extraction.feature_pipeline import FeatureExtractionPipeline

def test_url_lexical_extraction_standard():
    url = "https://www.google.com/search?q=test"
    feats = extract_url_features(url)
    assert feats["NoHttps"] == 0.0
    assert feats["NumDots"] >= 2.0
    assert feats["NumQueryComponents"] == 1.0
    assert feats["UrlLength"] == len(url)
    assert feats["IpAddress"] == 0.0

def test_url_phishing_patterns():
    url = "http://paypal.com.account-verification.attacker.net/login/auth.php?token=xyz"
    feats = extract_url_features(url)
    assert feats["NoHttps"] == 1.0
    assert feats["SubdomainLevel"] >= 2.0
    assert feats["DomainInSubdomains"] == 1.0 or feats["EmbeddedBrandName"] == 1.0
    assert feats["NumSensitiveWords"] >= 1.0

def test_ip_address_url():
    url = "http://192.168.1.100/admin/login"
    feats = extract_url_features(url)
    assert feats["IpAddress"] == 1.0
    assert is_ip_address("192.168.1.100") == 1

def test_feature_pipeline_exact_schema():
    pipeline = FeatureExtractionPipeline(enable_live_html=False)
    df, meta = pipeline.extract_features("https://github.com/explore")
    assert df.shape == (1, 48)
    assert list(df.columns) == FEATURE_NAMES
    assert meta["url_analysis"] is True
