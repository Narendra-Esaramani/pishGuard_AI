"""
Preprocessing, stratified splitting, and feature matrix preparation.
"""
import sys
from pathlib import Path
from typing import Tuple
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import PROCESSED_DATA_PATH
from feature_extraction.feature_schema import FEATURE_NAMES
from training.clean_dataset import clean_dataset

def prepare_train_test_split(
    test_size: float = 0.20,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Prepares stratified train and test splits with strict feature ordering.
    """
    if not PROCESSED_DATA_PATH.exists():
        df = clean_dataset()
    else:
        df = pd.read_csv(PROCESSED_DATA_PATH)
        
    if "id" in df.columns:
        df = df.drop(columns=["id"])
        
    X = df[FEATURE_NAMES]
    y = df["CLASS_LABEL"]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )
    
    return X_train, X_test, y_train, y_test

if __name__ == "__main__":
    X_tr, X_te, y_tr, y_te = prepare_train_test_split()
    print(f"Train split: X={X_tr.shape}, y={y_tr.shape} | Phishing ratio: {y_tr.mean():.4f}")
    print(f"Test split:  X={X_te.shape}, y={y_te.shape} | Phishing ratio: {y_te.mean():.4f}")
