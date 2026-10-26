"""
Unit tests for Explainable AI and Natural Language generation.
"""
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_schema import FEATURE_NAMES, DEFAULT_FEATURE_VALUES
from explainability.shap_explainer import ShapExplainerService
from explainability.explanation_generator import ExplanationGenerator

def test_shap_explanation_generation():
    df_sample = pd.DataFrame([DEFAULT_FEATURE_VALUES], columns=FEATURE_NAMES)
    explainer = ShapExplainerService()
    res = explainer.explain(df_sample, top_k=5)
    
    assert res["status"] == "success"
    assert len(res["top_factors"]) <= 5
    assert "all_contributions" in res

def test_human_explanation_translation():
    df_sample = pd.DataFrame([DEFAULT_FEATURE_VALUES], columns=FEATURE_NAMES)
    df_sample["SubdomainLevel"] = 4.0
    df_sample["UrlLength"] = 120.0
    
    gen = ExplanationGenerator()
    explanation = gen.generate_explanation(df_sample, is_phishing=True)
    
    assert len(explanation["summary_reasons"]) >= 3
    assert len(explanation["technical_factors"]) > 0
    assert "disclaimer" in explanation
