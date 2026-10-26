"""
Dataset loading and validation module.
"""
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import RAW_DATA_PATH

def load_raw_dataset(file_path: Path = RAW_DATA_PATH) -> pd.DataFrame:
    """Loads the raw phishing dataset from CSV with validation."""
    if not file_path.exists():
        raise FileNotFoundError(f"Raw dataset not found at {file_path}")
        
    df = pd.read_csv(file_path)
    if "CLASS_LABEL" not in df.columns:
        raise ValueError("Dataset missing mandatory target column 'CLASS_LABEL'")
        
    return df

if __name__ == "__main__":
    df = load_raw_dataset()
    print(f"Loaded raw dataset successfully. Shape: {df.shape}")
