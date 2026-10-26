"""
LIME (Local Interpretable Model-agnostic Explanations) fallback explainer.
"""
import sys
from pathlib import Path
from typing import Dict, Any
import numpy as np
import pandas as pd
from lime.lime_tabular import LimeTabularExplainer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import PROCESSED_DATA_PATH
from detection.predictor import PhishingPredictor

class LimeExplainerService:
    """
    Model-agnostic LIME explainer fallback.
    """
    def __init__(self):
        predictor = PhishingPredictor()
        self.model = predictor.model
        self.feature_names = predictor.feature_names
        
        # Load sample background data
        if PROCESSED_DATA_PATH.exists():
            df = pd.read_csv(PROCESSED_DATA_PATH)
            X = df[self.feature_names].values[:200]
        else:
            X = np.zeros((10, len(self.feature_names)))
            
        self.explainer = LimeTabularExplainer(
            training_data=X,
            feature_names=self.feature_names,
            class_names=["Legitimate", "Phishing"],
            mode="classification"
        )

    def explain(self, df_features: pd.DataFrame, num_features: int = 5) -> Dict[str, Any]:
        """Generates LIME explanation list for sample."""
        try:
            exp = self.explainer.explain_instance(
                df_features.iloc[0].values,
                self.model.predict_proba,
                num_features=num_features
            )
            lime_list = exp.as_list()
            return {
                "lime_factors": [{"rule": rule, "weight": round(weight, 4)} for rule, weight in lime_list],
                "status": "success"
            }
        except Exception as e:
            return {"lime_factors": [], "status": f"LIME fallback error: {str(e)}"}
