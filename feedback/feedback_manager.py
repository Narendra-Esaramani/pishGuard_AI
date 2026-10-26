"""
Feedback management and collection module.
Logs user feedback (Correct/Incorrect/Actual Label) to persistent CSV with deduplication.
"""
import sys
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FEEDBACK_CSV_PATH

FEEDBACK_COLUMNS = [
    "timestamp", "url_hash", "url", "predicted_label",
    "probability", "risk_score", "user_feedback",
    "actual_label", "comments", "is_verified"
]

class FeedbackManager:
    """
    Manages feedback collection, storage, and retrieval.
    """
    def __init__(self, feedback_file: Path = FEEDBACK_CSV_PATH):
        self.feedback_file = feedback_file
        self._ensure_storage()

    def _ensure_storage(self):
        """Ensures feedback CSV file exists with header."""
        self.feedback_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.feedback_file.exists() or self.feedback_file.stat().st_size == 0:
            df = pd.DataFrame(columns=FEEDBACK_COLUMNS)
            df.to_csv(self.feedback_file, index=False)

    def record_feedback(
        self,
        url: str,
        predicted_label: str,
        probability: float,
        risk_score: int,
        user_feedback: str,
        actual_label: Optional[str] = None,
        comments: str = "",
        is_verified: bool = False
    ) -> Dict[str, Any]:
        """
        Records user feedback entry to CSV.
        """
        url_clean = str(url).strip()
        url_hash = hashlib.sha256(url_clean.encode("utf-8")).hexdigest()[:16]
        now_str = datetime.datetime.now().isoformat()
        
        entry = {
            "timestamp": now_str,
            "url_hash": url_hash,
            "url": url_clean,
            "predicted_label": predicted_label,
            "probability": round(float(probability), 4),
            "risk_score": int(risk_score),
            "user_feedback": user_feedback,
            "actual_label": actual_label or "unknown",
            "comments": comments.strip(),
            "is_verified": is_verified
        }

        df_entry = pd.DataFrame([entry])
        df_entry.to_csv(self.feedback_file, mode="a", header=False, index=False)
        return entry

    def get_feedback_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent feedback submissions."""
        if not self.feedback_file.exists():
            return []
        try:
            df = pd.read_csv(self.feedback_file)
            if df.empty:
                return []
            return df.tail(limit).to_dict(orient="records")[::-1]
        except Exception:
            return []

    def get_summary_stats(self) -> Dict[str, Any]:
        """Calculates summary feedback statistics."""
        if not self.feedback_file.exists():
            return {"total_submissions": 0, "correct_count": 0, "incorrect_count": 0}
        try:
            df = pd.read_csv(self.feedback_file)
            total = len(df)
            if total == 0:
                return {"total_submissions": 0, "correct_count": 0, "incorrect_count": 0}
            correct = int((df["user_feedback"] == "Correct").sum())
            incorrect = int((df["user_feedback"] == "Incorrect").sum())
            verified = int((df["is_verified"] == True).sum())
            return {
                "total_submissions": total,
                "correct_count": correct,
                "incorrect_count": incorrect,
                "verified_count": verified,
                "user_satisfaction_rate": round(correct / total * 100, 1) if total > 0 else 0.0
            }
        except Exception:
            return {"total_submissions": 0, "correct_count": 0, "incorrect_count": 0}
