"""
Enhanced Model Predictor with Dynamic Class Resolution, Dual-Mode Adaptive Inference,
Probability Calibration, and Out-of-Distribution (OOD) Detection.
"""
import sys
import json
from pathlib import Path
from typing import Dict, Any, Tuple, List
import joblib
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import MODEL_PATH, FEATURE_NAMES_PATH, METADATA_PATH, MODELS_DIR
from feature_extraction.feature_schema import FEATURE_NAMES, URL_FEATURE_NAMES

class PhishingPredictor:
    """
    Production-grade predictor supporting adaptive dual pipelines (Full 48-feature vs Pure 28-feature URL),
    dynamic class index discovery, probability calibration, and Out-of-Distribution (OOD) diagnostics.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(PhishingPredictor, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Run training pipeline first.")
            
        # 1. Load Primary Calibrated Full Model
        self.model = joblib.load(MODEL_PATH)
        
        # 2. Load Calibrated Pure URL Model
        url_model_path = MODELS_DIR / "url_model.pkl"
        if url_model_path.exists():
            self.url_model = joblib.load(url_model_path)
        else:
            self.url_model = self.model
            
        # 3. Load Raw Model for SHAP
        raw_model_path = MODELS_DIR / "raw_phishing_model.pkl"
        if raw_model_path.exists():
            self.raw_model = joblib.load(raw_model_path)
        else:
            self.raw_model = self.model

        # 4. Feature Schemas
        self.feature_names = FEATURE_NAMES
        self.url_feature_names = URL_FEATURE_NAMES
        
        # 5. Load OOD Feature Profiles
        self.feature_profiles = {}
        profiles_path = MODELS_DIR / "feature_profiles.json"
        if profiles_path.exists():
            try:
                with open(profiles_path, "r", encoding="utf-8") as f:
                    self.feature_profiles = json.load(f)
            except Exception:
                pass

        # 6. Load Metadata
        self.metadata = {}
        if METADATA_PATH.exists():
            try:
                with open(METADATA_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception:
                pass
                
        self._initialized = True

    def check_out_of_distribution(self, df_features: pd.DataFrame) -> Dict[str, Any]:
        """
        Detects whether any extracted feature values are significantly outside training distribution.
        """
        if not self.feature_profiles:
            return {"is_ood": False, "anomalous_features": [], "warning": None}
            
        anomalies = []
        for col in df_features.columns:
            if col in self.feature_profiles:
                prof = self.feature_profiles[col]
                val = float(df_features[col].values[0])
                
                # Check if value exceeds 99th percentile or is below 1st percentile with notable magnitude
                if val > prof["p99"] and (val - prof["p99"]) > max(2.0, prof["std"]):
                    anomalies.append({
                        "feature": col,
                        "value": val,
                        "expected_range": f"{prof['p01']:.1f} - {prof['p99']:.1f}",
                        "type": "High Outlier"
                    })
                elif val < prof["p01"] and (prof["p01"] - val) > max(2.0, prof["std"]):
                    anomalies.append({
                        "feature": col,
                        "value": val,
                        "expected_range": f"{prof['p01']:.1f} - {prof['p99']:.1f}",
                        "type": "Low Outlier"
                    })
                    
        is_ood = len(anomalies) > 0
        warning_msg = None
        if is_ood:
            names = ", ".join([a["feature"] for a in anomalies[:3]])
            warning_msg = f"Some characteristics of this URL ({names}) differ significantly from the training distribution. Prediction confidence is adjusted."
            
        return {
            "is_ood": is_ood,
            "anomalous_features": anomalies,
            "anomaly_count": len(anomalies),
            "warning": warning_msg
        }

    def predict(
        self,
        df_features: pd.DataFrame,
        is_html_live: bool = False
    ) -> Tuple[int, float, Dict[str, float], Dict[str, Any]]:
        """
        Adaptive prediction selecting the optimal model based on HTML availability:
        - When HTML is live: uses Full 48-feature Calibrated Classifier.
        - When HTML is offline/unreachable: uses 28-feature Pure URL Calibrated Classifier
          to prevent defaulted HTML features from falsely suppressing phishing scores.
        
        Returns:
            (prediction, phishing_probability, probabilities_dict, diagnostic_metadata)
        """
        # 1. Check Out-of-Distribution status
        ood_info = self.check_out_of_distribution(df_features)

        # 2. Select appropriate model pipeline
        if is_html_live:
            active_model = self.model
            active_features = self.feature_names
            pipeline_mode = "Full Hybrid (48 features, Live HTML)"
            X_eval = df_features[self.feature_names]
        else:
            active_model = self.url_model
            active_features = self.url_feature_names
            pipeline_mode = "Pure URL & Domain (28 features, Offline-Resilient)"
            X_eval = df_features[self.url_feature_names]

        # 3. Dynamic class mapping discovery
        classes = list(getattr(active_model, "classes_", [0, 1]))
        phish_idx = classes.index(1) if 1 in classes else 1
        legit_idx = classes.index(0) if 0 in classes else 0

        # 4. Infer probabilities
        if hasattr(active_model, "predict_proba"):
            probs = active_model.predict_proba(X_eval)[0]
            prob_phish = float(probs[phish_idx])
            prob_legit = float(probs[legit_idx])
        elif hasattr(active_model, "decision_function"):
            score = float(active_model.decision_function(X_eval)[0])
            prob_phish = 1.0 / (1.0 + np.exp(-score))
            prob_legit = 1.0 - prob_phish
        else:
            raw_pred = active_model.predict(X_eval)[0]
            prob_phish = float(raw_pred)
            prob_legit = 1.0 - prob_phish

        # Ensure probabilities sum to 1.0
        total_p = prob_phish + prob_legit
        if total_p > 0:
            prob_phish = prob_phish / total_p
            prob_legit = prob_legit / total_p

        # Derive binary prediction at calibrated 0.50 threshold
        pred = 1 if prob_phish >= 0.50 else 0

        diag_meta = {
            "pipeline_mode": pipeline_mode,
            "features_used_count": len(active_features),
            "ood_info": ood_info,
            "is_calibrated": True
        }

        return pred, prob_phish, {"legitimate": prob_legit, "phishing": prob_phish}, diag_meta
