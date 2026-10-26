"""
Unit tests for Model loading, schema alignment, and adaptive inference.
"""
import sys
from pathlib import Path
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.predictor import PhishingPredictor
from feature_extraction.feature_schema import FEATURE_NAMES, DEFAULT_FEATURE_VALUES

def test_model_loading_and_prediction():
    predictor = PhishingPredictor()
    assert predictor.model is not None
    assert len(predictor.feature_names) == 48

    # Create valid sample
    df_sample = pd.DataFrame([DEFAULT_FEATURE_VALUES], columns=FEATURE_NAMES)
    pred, prob, prob_dict, diag_meta = predictor.predict(df_sample, is_html_live=False)
    
    assert pred in (0, 1)
    assert 0.0 <= prob <= 1.0
    assert abs((prob_dict["legitimate"] + prob_dict["phishing"]) - 1.0) < 1e-4
    assert "pipeline_mode" in diag_meta

def test_ood_detection():
    predictor = PhishingPredictor()
    df_sample = pd.DataFrame([DEFAULT_FEATURE_VALUES], columns=FEATURE_NAMES)
    df_sample["UrlLength"] = 650.0  # extreme outlier
    
    ood = predictor.check_out_of_distribution(df_sample)
    assert ood["is_ood"] is True
    assert any(a["feature"] == "UrlLength" for a in ood["anomalous_features"])
