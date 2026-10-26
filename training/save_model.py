"""
Best model selection, feature profiling (OOD statistical boundaries), and artifact serialization.
"""
import sys
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List
import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import (
    MODELS_DIR, MODEL_PATH, FEATURE_NAMES_PATH,
    METADATA_PATH, METRICS_PATH
)
from feature_extraction.feature_schema import FEATURE_NAMES, URL_FEATURE_NAMES
from training.train_models import train_and_calibrate_models
from training.feature_selection import compute_feature_importances

def compute_feature_distribution_profiles(df_features: pd.DataFrame) -> Dict[str, Any]:
    """
    Computes statistical profiles (min, max, p01, p99, mean, std) for Out-of-Distribution detection.
    """
    profiles = {}
    for col in df_features.columns:
        s = df_features[col]
        profiles[col] = {
            "min": float(s.min()),
            "max": float(s.max()),
            "p01": float(np.percentile(s, 1)),
            "p99": float(np.percentile(s, 99)),
            "mean": float(s.mean()),
            "std": float(s.std())
        }
    return profiles

def save_all_trained_models():
    """
    Trains, calibrates, computes OOD profiles, and saves production model artifacts.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    train_data = train_and_calibrate_models()
    
    # 1. Save Full Hybrid Model
    joblib.dump(train_data["calibrated_full_model"], MODEL_PATH)
    print(f"Saved Calibrated Full Model -> {MODEL_PATH}")
    
    # Save Raw Full Model (for SHAP TreeExplainer compatibility)
    raw_model_path = MODELS_DIR / "raw_phishing_model.pkl"
    joblib.dump(train_data["raw_full_model"], raw_model_path)
    print(f"Saved Raw XGBoost Model -> {raw_model_path}")
    
    # 2. Save Pure URL Model
    url_model_path = MODELS_DIR / "url_model.pkl"
    joblib.dump(train_data["calibrated_url_model"], url_model_path)
    print(f"Saved Calibrated Pure URL Model -> {url_model_path}")
    
    # 3. Save Feature Schemas
    joblib.dump(FEATURE_NAMES, FEATURE_NAMES_PATH)
    url_feat_path = MODELS_DIR / "url_feature_names.pkl"
    joblib.dump(URL_FEATURE_NAMES, url_feat_path)
    print(f"Saved Feature Schemas -> {FEATURE_NAMES_PATH}, {url_feat_path}")
    
    # 4. Compute & Save Feature Distribution Profiles for OOD Detection
    feature_profiles = compute_feature_distribution_profiles(train_data["X_train_full"])
    profiles_path = MODELS_DIR / "feature_profiles.json"
    with open(profiles_path, "w", encoding="utf-8") as f:
        json.dump(feature_profiles, f, indent=4)
    print(f"Saved OOD Feature Profiles -> {profiles_path}")

    # 5. Compile Feature Importances
    try:
        importances_ranked = compute_feature_importances()
        top_features = [{"feature": f, "importance": round(float(imp), 5)} for f, imp in importances_ranked]
    except Exception:
        top_features = []

    # 6. Model Metadata
    metadata = {
        "model_name": "Calibrated Adaptive XGBoost (Dual Pipeline with Evidence Synthesis)",
        "algorithm_class": "CalibratedClassifierCV(XGBClassifier)",
        "created_at": datetime.datetime.now().isoformat(),
        "optimal_decision_threshold": train_data["optimal_threshold"],
        "threshold_evaluations": train_data["threshold_evaluations"],
        "dataset_total_samples": 9581,
        "training_samples": 7664,
        "test_samples": 1917,
        "feature_count_hybrid": len(FEATURE_NAMES),
        "feature_count_url": len(URL_FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "top_features": top_features[:20],
        "metrics": train_data["calibrated_full_metrics"],
        "url_model_metrics": train_data["calibrated_url_metrics"],
        "all_model_benchmarks": {
            k: v["metrics"] for k, v in train_data["candidate_results"].items()
        }
    }
    
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"Saved Metadata -> {METADATA_PATH}")
    
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(train_data["calibrated_full_metrics"], f, indent=4)
    print(f"Saved Metrics -> {METRICS_PATH}")
    
    return metadata

if __name__ == "__main__":
    save_all_trained_models()
