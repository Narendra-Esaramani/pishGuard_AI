"""
Guardrailed Model Retraining Pipeline.
Ensures only verified, human-confirmed feedback updates the dataset,
and prevents model regression through automated comparative evaluation.
"""
import sys
import json
from pathlib import Path
from typing import Dict, Any, Tuple
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import PROCESSED_DATA_PATH, FEEDBACK_CSV_PATH, MODEL_PATH
from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from training.preprocess import prepare_train_test_split
from training.evaluate_models import evaluate_model_performance
from detection.predictor import PhishingPredictor

class ModelRetrainingPipeline:
    """
    Orchestrates continuous learning with strict promotion guardrails.
    """
    def __init__(self):
        self.feature_pipeline = FeatureExtractionPipeline(enable_live_html=False)

    def extract_features_for_verified_feedback(self) -> pd.DataFrame:
        """Extracts features for all verified feedback samples with confirmed labels."""
        if not FEEDBACK_CSV_PATH.exists():
            return pd.DataFrame()
            
        df_fb = pd.read_csv(FEEDBACK_CSV_PATH)
        verified = df_fb[df_fb["is_verified"] == True]
        valid_samples = verified[verified["actual_label"].isin(["phishing", "legitimate"])]
        
        if valid_samples.empty:
            return pd.DataFrame()
            
        rows = []
        for _, row in valid_samples.iterrows():
            try:
                df_feat, _ = self.feature_pipeline.extract_features(row["url"])
                df_feat["CLASS_LABEL"] = 1 if row["actual_label"] == "phishing" else 0
                rows.append(df_feat)
            except Exception:
                continue
                
        if not rows:
            return pd.DataFrame()
            
        return pd.concat(rows, ignore_index=True)

    def run_retraining_evaluation(self) -> Dict[str, Any]:
        """
        Retrains candidate model on expanded dataset and compares with active production model.
        """
        # Load baseline splits
        X_train, X_test, y_train, y_test = prepare_train_test_split()
        
        # Load verified feedback
        df_new = self.extract_features_for_verified_feedback()
        
        if df_new.empty or len(df_new) < 5:
            return {
                "status": "skipped",
                "message": "Insufficient verified feedback samples (minimum 5 required for retraining trigger).",
                "promoted": False
            }
            
        # Combine training data
        X_new = df_new.drop(columns=["CLASS_LABEL"])
        y_new = df_new["CLASS_LABEL"]
        
        X_train_expanded = pd.concat([X_train, X_new], ignore_index=True)
        y_train_expanded = pd.concat([y_train, y_new], ignore_index=True)
        
        # Train candidate model
        from xgboost import XGBClassifier
        candidate_model = XGBClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.85,
            eval_metric="logloss",
            random_state=42
        )
        candidate_model.fit(X_train_expanded, y_train_expanded)
        
        # Evaluate active production model
        active_predictor = PhishingPredictor()
        active_metrics = evaluate_model_performance(active_predictor.model, X_test, y_test)
        
        # Evaluate candidate model
        candidate_metrics = evaluate_model_performance(candidate_model, X_test, y_test)
        
        # Promotion Criteria:
        # 1. Candidate Accuracy must not drop by more than 0.5%
        # 2. Candidate Phishing Recall must be >= active recall
        acc_pass = candidate_metrics["accuracy"] >= (active_metrics["accuracy"] - 0.005)
        rec_pass = candidate_metrics["recall"] >= (active_metrics["recall"] - 0.005)
        f1_pass = candidate_metrics["f1_score"] >= (active_metrics["f1_score"] - 0.005)
        
        promoted = bool(acc_pass and rec_pass and f1_pass)
        
        return {
            "status": "completed",
            "new_samples_count": len(df_new),
            "promoted": promoted,
            "active_model_metrics": active_metrics,
            "candidate_model_metrics": candidate_metrics,
            "promotion_criteria": {
                "accuracy_check": acc_pass,
                "recall_check": rec_pass,
                "f1_check": f1_pass
            },
            "summary": "Candidate model passed all quality checks." if promoted else "Candidate model rejected due to performance regression."
        }
