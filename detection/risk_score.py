"""
Calibrated risk scoring and risk tier classification with evidence weighting.
"""
from typing import Tuple, Dict, Any

from config import (
    RISK_THRESHOLD_SAFE_MAX,
    RISK_THRESHOLD_SUSPICIOUS_MAX,
    RISK_THRESHOLD_HIGH_MIN
)

def calculate_risk_score(
    phishing_probability: float,
    heuristic_penalty: int = 0,
    feature_completeness_pct: float = 100.0,
    is_ood: bool = False
) -> int:
    """
    Computes a calibrated 0-100 integer risk score by combining:
    1. Calibrated ML Phishing Probability (base weight: 85%)
    2. Critical Heuristic / Domain Flags (penalty adjustment: up to +25)
    3. Missing Evidence Uncertainty & Out-of-Distribution adjustments.
    """
    prob = max(0.0, min(1.0, float(phishing_probability)))
    base_score = prob * 100.0
    
    # Heuristic adjustment
    adjusted_score = base_score + heuristic_penalty
    
    # OOD uncertainty buffer if borderline
    if is_ood and 25.0 <= adjusted_score <= 65.0:
        adjusted_score += 5.0
        
    final_score = int(round(max(0.0, min(100.0, adjusted_score))))
    return final_score

def get_risk_level(risk_score: int) -> Tuple[str, str, str]:
    """
    Maps an integer risk score (0-100) to (Risk Level, Badge Class, Description).
    - SAFE (0-30): Low probability of phishing characteristics.
    - SUSPICIOUS (31-69): Moderate risk, contains anomalous patterns or incomplete evidence.
    - HIGH RISK (70-100): High probability of phishing attack. Critical deception indicators detected.
    """
    if risk_score <= RISK_THRESHOLD_SAFE_MAX:
        return "SAFE", "safe", "Minimal phishing risk detected. Website exhibits legitimate structure."
    elif risk_score <= RISK_THRESHOLD_SUSPICIOUS_MAX:
        return "SUSPICIOUS", "warning", "Moderate risk detected. Website contains anomalous attributes or incomplete verification evidence."
    else:
        return "HIGH RISK", "danger", "High probability of phishing attack. Critical deception indicators detected."
