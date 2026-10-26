"""
Evaluation metrics computation module for Phishing Detection Research.
"""
from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    matthews_corrcoef, brier_score_loss
)

def compute_all_metrics(y_true: List[int], y_pred: List[int], y_prob: List[float]) -> Dict[str, Any]:
    """Calculates full cybersecurity and statistical performance metrics."""
    y_t = np.array(y_true)
    y_p = np.array(y_pred)
    y_pr = np.array(y_prob)
    
    cm = confusion_matrix(y_t, y_p)
    tn, fp, fn, tp = cm.ravel()
    
    acc = float(accuracy_score(y_t, y_p))
    prec = float(precision_score(y_t, y_p, zero_division=0))
    rec = float(recall_score(y_t, y_p, zero_division=0))  # Phishing Sensitivity
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0  # Legitimate Specificity
    f1 = float(f1_score(y_t, y_p, zero_division=0))
    mcc = float(matthews_corrcoef(y_t, y_p))
    brier = float(brier_score_loss(y_t, y_pr))
    
    try:
        auc = float(roc_auc_score(y_t, y_pr))
    except Exception:
        auc = 0.0
        
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    
    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "specificity": round(spec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "mcc": round(mcc, 4),
        "brier_score": round(brier, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        }
    }
