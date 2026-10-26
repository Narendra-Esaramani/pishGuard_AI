"""
Model evaluation, cybersecurity metrics, and performance benchmarking.
"""
import sys
import json
from pathlib import Path
from typing import Dict, Any
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.metrics import compute_all_metrics
from training.preprocess import prepare_train_test_split

def evaluate_model_performance(model, X_test, y_test) -> Dict[str, Any]:
    """Computes comprehensive classification and cybersecurity metrics."""
    y_pred = model.predict(X_test)
    
    if hasattr(model, "predict_proba"):
        classes = list(getattr(model, "classes_", [0, 1]))
        phish_idx = classes.index(1) if 1 in classes else 1
        y_prob = model.predict_proba(X_test)[:, phish_idx]
    elif hasattr(model, "decision_function"):
        df = model.decision_function(X_test)
        y_prob = (df - df.min()) / (df.max() - df.min() + 1e-9)
    else:
        y_prob = y_pred
        
    return compute_all_metrics(y_test.tolist(), y_pred.tolist(), y_prob.tolist())
