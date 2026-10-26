"""
Unit tests for Feedback management and retraining guardrails.
"""
import sys
from pathlib import Path
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feedback.feedback_manager import FeedbackManager
from feedback.retraining_pipeline import ModelRetrainingPipeline

def test_feedback_recording_and_history():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        
    mgr = FeedbackManager(feedback_file=tmp_path)
    entry = mgr.record_feedback(
        url="https://test-site.org",
        predicted_label="legitimate",
        probability=0.05,
        risk_score=5,
        user_feedback="Correct",
        actual_label="legitimate"
    )
    
    assert entry["url"] == "https://test-site.org"
    history = mgr.get_feedback_history(limit=5)
    assert len(history) == 1
    assert history[0]["url"] == "https://test-site.org"

    stats = mgr.get_summary_stats()
    assert stats["total_submissions"] == 1
    assert stats["correct_count"] == 1
    assert stats["user_satisfaction_rate"] == 100.0

def test_retraining_insufficient_samples_guardrail():
    retrainer = ModelRetrainingPipeline()
    res = retrainer.run_retraining_evaluation()
    assert res["promoted"] is False
    assert res["status"] in ("skipped", "completed")
