"""
SHAP-based Explainable AI module using TreeExplainer on tree ensembles.
Calculates local feature attributions with caching.
"""
import sys
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
import pandas as pd
import shap

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.predictor import PhishingPredictor

class ShapExplainerService:
    """
    Service for generating exact SHAP feature attributions using TreeExplainer.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(ShapExplainerService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        predictor = PhishingPredictor()
        # Use raw XGBoost model for exact tree traversal
        self.raw_model = getattr(predictor, "raw_model", predictor.model)
        self.feature_names = predictor.feature_names
        
        # Initialize SHAP TreeExplainer
        try:
            self.explainer = shap.TreeExplainer(self.raw_model)
        except Exception:
            try:
                self.explainer = shap.Explainer(self.raw_model)
            except Exception:
                self.explainer = None
            
        self._initialized = True

    def explain(self, df_features: pd.DataFrame, top_k: int = 6) -> Dict[str, Any]:
        """
        Calculates SHAP values for a single sample.
        """
        if self.explainer is None:
            return {"base_value": 0.0, "top_factors": [], "all_contributions": {}, "status": "Explainer not initialized"}
            
        try:
            shap_values = self.explainer(df_features[self.feature_names])
            
            # Handle 2D / 3D output shapes
            if len(shap_values.values.shape) == 3:
                vals = shap_values.values[0, :, 1]
                base_val = float(shap_values.base_values[0, 1])
            elif len(shap_values.values.shape) == 2:
                vals = shap_values.values[0]
                base_val = float(shap_values.base_values[0]) if hasattr(shap_values.base_values, "__len__") else float(shap_values.base_values)
            else:
                vals = np.array(shap_values.values).flatten()
                base_val = 0.0

            feature_contributions = []
            for i, name in enumerate(self.feature_names):
                feat_val = float(df_features[name].values[0])
                shap_val = float(vals[i])
                feature_contributions.append({
                    "feature": name,
                    "value": feat_val,
                    "shap_value": round(shap_val, 4),
                    "impact": "phishing" if shap_val > 0 else "legitimate",
                    "abs_impact": abs(shap_val)
                })

            # Sort by absolute SHAP impact
            ranked = sorted(feature_contributions, key=lambda x: x["abs_impact"], reverse=True)
            top_factors = ranked[:top_k]
            
            return {
                "base_value": round(base_val, 4),
                "top_factors": top_factors,
                "all_contributions": {item["feature"]: item for item in feature_contributions},
                "status": "success"
            }
            
        except Exception as e:
            return {
                "base_value": 0.0,
                "top_factors": [],
                "all_contributions": {},
                "status": f"SHAP calculation fallback: {str(e)}"
            }
