"""
Automated Regression and Robustness Test Suite.
Verifies that all components, feature extractors, probability calibrations,
thresholds, and evidence synthesis rules operate consistently without regressions.
"""
import sys
import json
from pathlib import Path
import pytest
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from feature_extraction.feature_schema import FEATURE_NAMES, URL_FEATURE_NAMES
from detection.predictor import PhishingPredictor
from detection.decision_engine import evaluate_decision
from detection.evidence_synthesis import EvidenceSynthesisEngine

@pytest.fixture
def pipeline():
    return FeatureExtractionPipeline(enable_live_html=False)

@pytest.fixture
def predictor():
    return PhishingPredictor()

def test_legitimate_url_regression(pipeline, predictor):
    """Verifies that authentic top-tier domains receive SAFE verdicts."""
    legit_samples = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://www.python.org"
    ]
    for url in legit_samples:
        df, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df, is_html_live=False)
        decision = evaluate_decision(pred, prob, df, meta, diag)
        assert decision["verdict"] == "LIKELY LEGITIMATE", f"Failed on {url}"
        assert decision["risk_score"] <= 30
        assert decision["risk_level"] == "SAFE"

def test_high_risk_phishing_url_regression(pipeline, predictor):
    """Verifies that active credential-harvesting phishing patterns receive threat flags."""
    phish_samples = [
        "http://paypal-security-verification.account-update.net/login.php?token=98234",
        "http://appleid.apple.com.manage-account.info/auth/verify?session=x9",
        "http://192.168.1.100/admin/secure_portal/login.php"
    ]
    for url in phish_samples:
        df, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df, is_html_live=False)
        decision = evaluate_decision(pred, prob, df, meta, diag)
        assert decision["risk_score"] >= 40, f"Failed on {url}: Risk was {decision['risk_score']}"
        assert decision["verdict"] in ("LIKELY PHISHING", "SUSPICIOUS (NEEDS REVIEW)")

def test_contradictory_and_incomplete_evidence_handling(pipeline, predictor):
    """Verifies that unresolvable domains or contradictory signals are flagged for review."""
    ambiguous_samples = [
        "https://personasenlinea.net/",
        "http://ofcprune.online",
        "http://remote-aquent.com"
    ]
    for url in ambiguous_samples:
        df, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df, is_html_live=False)
        decision = evaluate_decision(pred, prob, df, meta, diag)
        assert decision["verdict"] == "SUSPICIOUS (NEEDS REVIEW)", f"Failed on {url}"
        assert 31 <= decision["risk_score"] <= 69

def test_feature_consistency_and_completeness(pipeline):
    """Verifies that feature extraction always returns exact 48 columns in expected order."""
    test_url = "https://example.com/test/path?q=1&param=value"
    df, meta = pipeline.extract_features(test_url)
    assert list(df.columns) == FEATURE_NAMES
    assert df.shape == (1, 48)
    assert not df.isnull().any().any()
    assert meta["features_extracted_count"] == 28
    assert meta["total_features_count"] == 48

def test_dynamic_class_mapping_assertion(predictor):
    """Ensures model.classes_ resolves to [0, 1] without inversion."""
    classes = list(getattr(predictor.model, "classes_", [0, 1]))
    assert classes == [0, 1], f"Unexpected class mapping: {classes}"
    if hasattr(predictor, "url_model"):
        url_classes = list(getattr(predictor.url_model, "classes_", [0, 1]))
        assert url_classes == [0, 1], f"Unexpected URL model class mapping: {url_classes}"

def test_probability_calibration_boundaries(predictor):
    """Ensures calibrated probabilities always sum to 1.0 and stay in [0.0, 1.0]."""
    df_dummy = pd.DataFrame([{col: 0.0 for col in FEATURE_NAMES}])
    pred, prob, prob_dict, diag = predictor.predict(df_dummy, is_html_live=False)
    assert 0.0 <= prob <= 1.0
    assert abs((prob_dict["legitimate"] + prob_dict["phishing"]) - 1.0) < 1e-4
