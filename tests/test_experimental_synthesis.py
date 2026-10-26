"""
Unit test suite for the Experimental Evidence-Synthesis Layer.
Tests:
1. Legitimate root URLs
2. Legitimate documentation pages with deep hierarchical paths
3. Legitimate nested scientific pages
4. Suspicious hostnames with multiple hyphens or raw IP
5. Deceptive subdomains (brand camouflage)
6. Phishing URLs with deep paths
7. URLs with missing HTML evidence (uncertainty handling)
"""
import sys
from pathlib import Path
import pytest
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from detection.predictor import PhishingPredictor
from detection.decision_engine import evaluate_decision

@pytest.fixture
def pipeline():
    return FeatureExtractionPipeline(enable_live_html=False)

@pytest.fixture
def predictor():
    return PhishingPredictor()

def test_legitimate_root_urls(pipeline, predictor):
    """Verifies that authentic root domains receive SAFE verdicts in experimental mode."""
    root_urls = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://www.python.org"
    ]
    for url in root_urls:
        df_feat, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
        decision = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True)
        assert decision["verdict"] == "LIKELY LEGITIMATE"
        assert decision["risk_level"] == "SAFE"
        assert decision["risk_score"] <= 30

def test_legitimate_documentation_pages(pipeline, predictor):
    """Verifies that documentation pages with deep paths are NOT falsely classified as PHISHING."""
    doc_urls = [
        "https://docs.python.org/3/library/socket.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    ]
    for url in doc_urls:
        df_feat, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
        decision = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True)
        # Should not be LIKELY PHISHING (verdict should be SAFE or SUSPICIOUS)
        assert decision["verdict"] in ("LIKELY LEGITIMATE", "SUSPICIOUS (NEEDS REVIEW)"), f"False positive on {url}"
        assert decision["risk_score"] < 70, f"Risk score too high on {url}: {decision['risk_score']}"

def test_legitimate_nested_pages(pipeline, predictor):
    """Verifies that legitimate scientific or article nested pages are handled safely."""
    nested_urls = [
        "https://www.nature.com/articles/nature14539",
        "https://www.nytimes.com/section/technology"
    ]
    for url in nested_urls:
        df_feat, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
        decision = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True)
        assert decision["risk_level"] in ("SAFE", "SUSPICIOUS")
        assert decision["risk_score"] < 70

def test_deceptive_subdomains(pipeline, predictor):
    """Verifies that brand camouflage in subdomains is flagged as a severe threat."""
    spoof_urls = [
        "http://appleid.apple.com.manage-account.info/auth/verify?session=x9",
        "http://paypal.com.account-update-portal.xyz/cgi-bin/webscr"
    ]
    for url in spoof_urls:
        df_feat, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
        decision = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True)
        assert decision["verdict"] == "LIKELY PHISHING"
        assert decision["risk_score"] >= 70

def test_raw_ip_and_suspicious_hostnames(pipeline, predictor):
    """Verifies that raw IP hostnames and multi-hyphen hostnames receive high risk flags."""
    raw_ip_url = "http://192.168.1.100/admin/secure_portal/login.php"
    df_feat, meta = pipeline.extract_features(raw_ip_url)
    pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
    decision = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True)
    assert decision["verdict"] == "LIKELY PHISHING"
    assert decision["risk_score"] >= 70

def test_phishing_deep_paths(pipeline, predictor):
    """Verifies that genuine phishing campaigns with deep paths remain correctly flagged."""
    phish_deep_urls = [
        "http://netflix-billing-update.account-support.com/update_payment.php",
        "http://paypal-security-verification.account-update.net/login.php?token=98234"
    ]
    for url in phish_deep_urls:
        df_feat, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
        decision = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True)
        assert decision["verdict"] == "LIKELY PHISHING"
        assert decision["risk_score"] >= 70

def test_offline_html_uncertainty_handling(pipeline, predictor):
    """Verifies that missing HTML features do not produce arbitrary false certainty."""
    url = "https://www.microsoft.com/en-us/security"
    df_feat, meta = pipeline.extract_features(url)
    pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
    decision = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True)
    # With security keyword in path and offline HTML, it should be mediated to SUSPICIOUS (NEEDS REVIEW)
    assert decision["verdict"] == "SUSPICIOUS (NEEDS REVIEW)"
    assert 35 <= decision["risk_score"] <= 60
