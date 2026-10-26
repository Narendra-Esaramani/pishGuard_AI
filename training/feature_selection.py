"""
Feature importance analysis and ranking module.
"""
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.preprocess import prepare_train_test_split

def compute_feature_importances() -> List[Tuple[str, float]]:
    """Calculates feature importance rankings using Random Forest."""
    X_train, _, y_train, _ = prepare_train_test_split()
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    importances = rf.feature_importances_
    features = list(X_train.columns)
    
    ranked = sorted(zip(features, importances), key=lambda x: x[1], reverse=True)
    return ranked

if __name__ == "__main__":
    ranked = compute_feature_importances()
    print("=" * 60)
    print("TOP 15 MOST INFLUENTIAL FEATURES (RANDOM FOREST GINI IMPORTANCE)")
    print("=" * 60)
    for i, (name, imp) in enumerate(ranked[:15], 1):
        print(f"{i:2d}. {name:<35} : {imp:.5f} ({imp*100:.2f}%)")
