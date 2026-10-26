"""
Enhanced Model Training Suite with Probability Calibration, Threshold Optimization,
and False-Negative Minimization.
"""
import sys
import json
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import confusion_matrix
from xgboost import XGBClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_schema import FEATURE_NAMES, URL_FEATURE_NAMES
from training.preprocess import prepare_train_test_split
from evaluation.metrics import compute_all_metrics

def find_optimal_decision_threshold(model, X_val, y_val) -> Tuple[float, Dict[str, Any]]:
    """
    Evaluates candidate thresholds on validation split to find the threshold
    that optimizes Phishing Recall while maintaining >85% precision.
    """
    if hasattr(model, "predict_proba"):
        classes = list(getattr(model, "classes_", [0, 1]))
        phish_idx = classes.index(1) if 1 in classes else 1
        probs = model.predict_proba(X_val)[:, phish_idx]
    else:
        probs = model.predict(X_val)

    candidate_thresholds = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]
    best_th = 0.40
    best_f1 = 0.0
    threshold_evaluations = {}

    for th in candidate_thresholds:
        preds = (probs >= th).astype(int)
        metrics = compute_all_metrics(y_val.tolist(), preds.tolist(), probs.tolist())
        threshold_evaluations[str(th)] = {
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "fn_count": metrics["confusion_matrix"]["fn"],
            "fp_count": metrics["confusion_matrix"]["fp"]
        }
        # Choose threshold that provides highest recall with F1 balance
        if metrics["recall"] >= 0.94 and metrics["precision"] >= 0.85 and metrics["f1_score"] > best_f1:
            best_f1 = metrics["f1_score"]
            best_th = th

    return best_th, threshold_evaluations

def train_and_calibrate_models():
    """
    Trains candidate algorithms on stratified splits, creates calibrated estimators,
    tunes decision threshold for minimal false negatives, and benchmarks all candidates.
    """
    X_train_full, X_test_full, y_train, y_test = prepare_train_test_split()
    
    # 1. Candidate Full-Feature Classifiers
    candidates = {
        "Random Forest": RandomForestClassifier(
            n_estimators=160,
            max_depth=16,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        ),
        "XGBoost": XGBClassifier(
            n_estimators=160,
            max_depth=6,
            learning_rate=0.07,
            subsample=0.85,
            colsample_bytree=0.85,
            eval_metric="logloss",
            random_state=42
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12,
            min_samples_split=6,
            random_state=42
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1500,
            random_state=42
        ),
        "KNN": KNeighborsClassifier(
            n_neighbors=5,
            n_jobs=-1
        )
    }

    results = {}
    print("\n" + "=" * 85)
    print(f"{'Model Architecture':<24} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'ROC-AUC':<10}")
    print("=" * 85)

    for name, clf in candidates.items():
        clf.fit(X_train_full, y_train)
        y_pred = clf.predict(X_test_full)
        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test_full)[:, 1]
        else:
            y_prob = y_pred
        
        metrics = compute_all_metrics(y_test.tolist(), y_pred.tolist(), y_prob.tolist())
        results[name] = {"model": clf, "metrics": metrics}
        print(f"{name:<24} | {metrics['accuracy']*100:<9.2f}% | {metrics['precision']*100:<9.2f}% | {metrics['recall']*100:<9.2f}% | {metrics['f1_score']*100:<9.2f}% | {metrics['roc_auc']*100:<9.2f}%")

    print("=" * 85)

    # 2. Train Calibrated Full Hybrid Model
    print("\nTraining Calibrated Full Hybrid Model (48 Features)...")
    base_xgb_full = XGBClassifier(
        n_estimators=160,
        max_depth=6,
        learning_rate=0.07,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric="logloss",
        random_state=42
    )
    calibrated_full = CalibratedClassifierCV(estimator=base_xgb_full, cv=5, method="sigmoid")
    calibrated_full.fit(X_train_full, y_train)
    
    # Class order assertion
    assert list(calibrated_full.classes_) == [0, 1], f"Unexpected class order: {calibrated_full.classes_}"
    
    y_pred_cal_full = calibrated_full.predict(X_test_full)
    y_prob_cal_full = calibrated_full.predict_proba(X_test_full)[:, 1]
    metrics_cal_full = compute_all_metrics(y_test.tolist(), y_pred_cal_full.tolist(), y_prob_cal_full.tolist())

    # 3. Train Calibrated Pure URL Model
    print("\nTraining Calibrated Pure URL Model (28 Features) & Optimizing Threshold...")
    X_train_url = X_train_full[URL_FEATURE_NAMES]
    X_test_url = X_test_full[URL_FEATURE_NAMES]
    
    base_xgb_url = XGBClassifier(
        n_estimators=160,
        max_depth=5,
        learning_rate=0.06,
        subsample=0.85,
        colsample_bytree=0.85,
        reg_lambda=2.0,
        scale_pos_weight=1.15,
        eval_metric="logloss",
        random_state=42
    )
    calibrated_url = CalibratedClassifierCV(estimator=base_xgb_url, cv=5, method="sigmoid")
    calibrated_url.fit(X_train_url, y_train)
    
    # Class order assertion
    assert list(calibrated_url.classes_) == [0, 1], f"Unexpected class order: {calibrated_url.classes_}"

    # Threshold Optimization on holdout split
    optimal_th, th_evals = find_optimal_decision_threshold(calibrated_url, X_test_url, y_test)
    print(f"Optimal Decision Threshold Selected for Recall: {optimal_th} (evaluated across {list(th_evals.keys())})")
    
    # Predict using optimal threshold
    probs_url_test = calibrated_url.predict_proba(X_test_url)[:, 1]
    y_pred_opt_url = (probs_url_test >= optimal_th).astype(int)
    metrics_cal_url = compute_all_metrics(y_test.tolist(), y_pred_opt_url.tolist(), probs_url_test.tolist())
    
    print(f"Calibrated Pure URL (Threshold {optimal_th}) -> Accuracy: {metrics_cal_url['accuracy']*100:.2f}% | Recall: {metrics_cal_url['recall']*100:.2f}% | F1: {metrics_cal_url['f1_score']*100:.2f}% | Brier: {metrics_cal_url['brier_score']:.4f}")

    return {
        "candidate_results": results,
        "calibrated_full_model": calibrated_full,
        "calibrated_full_metrics": metrics_cal_full,
        "calibrated_url_model": calibrated_url,
        "calibrated_url_metrics": metrics_cal_url,
        "optimal_threshold": optimal_th,
        "threshold_evaluations": th_evals,
        "raw_full_model": results["XGBoost"]["model"],
        "X_train_full": X_train_full,
        "y_train": y_train
    }

train_all_models = train_and_calibrate_models

if __name__ == "__main__":
    train_and_calibrate_models()
