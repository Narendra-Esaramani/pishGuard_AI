"""
Unit tests for Risk Scoring and categorical level mapping.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.risk_score import calculate_risk_score, get_risk_level

def test_risk_score_boundaries():
    assert calculate_risk_score(0.0) == 0
    assert calculate_risk_score(1.0) == 100
    assert calculate_risk_score(0.25) == 25
    assert calculate_risk_score(0.75) == 75

def test_risk_level_mapping():
    level_safe, badge_safe, _ = get_risk_level(20)
    assert level_safe == "SAFE"
    assert badge_safe == "safe"

    level_susp, badge_susp, _ = get_risk_level(50)
    assert level_susp == "SUSPICIOUS"
    assert badge_susp == "warning"

    level_high, badge_high, _ = get_risk_level(85)
    assert level_high == "HIGH RISK"
    assert badge_high == "danger"
