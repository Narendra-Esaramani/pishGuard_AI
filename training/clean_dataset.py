"""
Dataset cleaning and integrity verification.
"""
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import RAW_DATA_PATH, PROCESSED_DATA_PATH
from training.load_dataset import load_raw_dataset

def clean_dataset(raw_path: Path = RAW_DATA_PATH, output_path: Path = PROCESSED_DATA_PATH) -> pd.DataFrame:
    """Cleans dataset, drops identifier column, removes any corrupted rows, and saves clean copy."""
    df = load_raw_dataset(raw_path)
    
    # Drop 'id' column if present
    if "id" in df.columns:
        df = df.drop(columns=["id"])
        
    # Drop duplicates if any
    initial_len = len(df)
    df = df.drop_duplicates()
    
    # Handle any null values
    df = df.dropna()
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Clean dataset saved to {output_path}. Shape: {df.shape} (Removed {initial_len - len(df)} duplicate/corrupted rows)")
    return df

if __name__ == "__main__":
    clean_dataset()
