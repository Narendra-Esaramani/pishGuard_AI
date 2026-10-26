"""
Evidence-Based Multi-Factor Decision Engine with Contradiction Resolution.
Synthesizes ML prediction, URL syntax signals, domain availability/telemetry,
HTML DOM evidence, and evidence confidence via the Evidence Synthesis Layer.
"""
from typing import Dict, Any, List
import pandas as pd

from .risk_score import calculate_risk_score, get_risk_level
from .evidence_synthesis import EvidenceSynthesisEngine

def evaluate_decision(
    prediction: int,
    phishing_probability: float,
    df_features: pd.DataFrame,
    extraction_meta: Dict[str, Any],
    diag_meta: Dict[str, Any] = None,
    use_experimental: bool = None,
    decision_threshold: float = None
) -> Dict[str, Any]:
    """
    Evaluates composite security decision combining ML output, feature availability,
    OOD anomaly detection, domain reputation evidence, and multi-channel evidence synthesis.
    Supports switchable experimental synthesis mode.
    """
    if diag_meta is None:
        diag_meta = {}

    from config import ENABLE_EXPERIMENTAL_SYNTHESIS, EXPERIMENTAL_DECISION_THRESHOLD
    if use_experimental is None:
        use_experimental = ENABLE_EXPERIMENTAL_SYNTHESIS
    if decision_threshold is None:
        decision_threshold = EXPERIMENTAL_DECISION_THRESHOLD
        
    feat_row = df_features.iloc[0].to_dict()
    domain_meta = extraction_meta.get("domain_metadata", {})
    ood_info = diag_meta.get("ood_info", {})
    completeness_pct = extraction_meta.get("feature_completeness_pct", 100.0)
    
    # 1. Evaluate Multi-Channel Evidence Synthesis (Baseline or Experimental)
    if use_experimental:
        synthesis = EvidenceSynthesisEngine.synthesize_channels_experimental(
            ml_prediction=prediction,
            phishing_probability=phishing_probability,
            df_features=df_features,
            extraction_meta=extraction_meta,
            diag_meta=diag_meta,
            decision_threshold=decision_threshold
        )
    else:
        synthesis = EvidenceSynthesisEngine.synthesize_channels(
            ml_prediction=prediction,
            phishing_probability=phishing_probability,
            df_features=df_features,
            extraction_meta=extraction_meta,
            diag_meta=diag_meta
        )
    
    verdict = synthesis["synthesized_verdict"]
    risk_level = synthesis["synthesized_risk_level"]
    badge_class = synthesis["synthesized_badge"]
    risk_score = synthesis["synthesized_risk_score"]
    verdict_summary = synthesis["evidence_verdict_rationale"]

    
    # 2. Critical Flags & Contradiction Notices
    critical_flags: List[str] = []
    
    if synthesis["is_contradictory"]:
        for reason in synthesis["contradiction_reasons"]:
            critical_flags.append(f"Telemetry Contradiction: {reason}")
            
    if feat_row.get("InsecureForms", 0) == 1:
        critical_flags.append("Insecure form submission (transmitting credentials over unencrypted HTTP).")
    if feat_row.get("AbnormalFormAction", 0) == 1:
        critical_flags.append("Abnormal form action (empty action, javascript: execution, or about:blank).")
    if feat_row.get("IpAddress", 0) == 1:
        critical_flags.append("Hostname is a raw IP address rather than a registered domain name.")
    if feat_row.get("DomainInSubdomains", 0) == 1 or feat_row.get("EmbeddedBrandName", 0) == 1:
        critical_flags.append("Brand name spoofing detected in subdomains or URL path.")
    if domain_meta.get("dns_resolved") is False and not domain_meta.get("is_ip_address"):
        critical_flags.append("Domain does not resolve via standard DNS (potential inactive/taken-down campaign domain).")

    # 3. Confidence Rating
    is_ood = ood_info.get("is_ood", False)
    if synthesis["is_contradictory"] or not extraction_meta.get("html_analysis", False):
        confidence = "MEDIUM (PARTIAL/CONTRADICTORY EVIDENCE)"
        confidence_desc = "Decision mediated by evidence synthesis layer due to incomplete or contradictory signals."
    elif is_ood:
        confidence = "LOW (OUT-OF-DISTRIBUTION)"
        confidence_desc = "Certain URL properties differ notably from training data."
    elif abs(phishing_probability - 0.50) >= 0.30 and completeness_pct >= 80.0:
        confidence = "HIGH"
        confidence_desc = "Model prediction is supported by strong evidence and complete feature telemetry."
    else:
        confidence = "MODERATE"
        confidence_desc = "Sufficient evidence available for assessment."

    # 4. Evidence Summary Dict
    evidence_summary = {
        "url_evidence": [
            f"Length: {int(feat_row.get('UrlLength', 0))} chars (RT: {int(feat_row.get('UrlLengthRT', 1))})",
            f"Subdomains: {int(feat_row.get('SubdomainLevel', 0))} (RT: {int(feat_row.get('SubdomainLevelRT', 1))})",
            f"Dots: {int(feat_row.get('NumDots', 0))}, Hyphens: {int(feat_row.get('NumDash', 0))}",
            f"HTTPS Scheme: {'Yes' if feat_row.get('NoHttps', 0) == 0 else 'No (HTTP)'}",
            f"Sensitive Words: {int(feat_row.get('NumSensitiveWords', 0))}"
        ],
        "domain_evidence": [
            f"Registered Domain: {domain_meta.get('registered_domain', 'N/A')}",
            f"TLD: .{domain_meta.get('tld', 'N/A')}",
            f"DNS Resolved: {'Yes' if domain_meta.get('dns_resolved') else 'No / Failed'}",
            f"HTTPS Handshake: {'Yes' if domain_meta.get('https_available') else 'No / Inactive'}"
        ],
        "html_evidence": [
            extraction_meta.get("html_message", "HTML analysis unavailable.")
        ],
        "ml_evidence": {
            "pipeline_mode": diag_meta.get("pipeline_mode", "Adaptive Hybrid"),
            "model_probability": round(phishing_probability, 4),
            "calibrated": diag_meta.get("is_calibrated", True),
            "feature_completeness": f"{extraction_meta.get('features_extracted_count', 48)}/{extraction_meta.get('total_features_count', 48)} ({completeness_pct}%)",
            "is_ood": is_ood,
            "is_contradictory": synthesis["is_contradictory"]
        },
        "channels": synthesis["channels"]
    }

    _, _, risk_desc = get_risk_level(risk_score)

    return {
        "verdict": verdict,
        "verdict_summary": verdict_summary,
        "prediction_class": prediction,
        "is_phishing": bool(risk_score >= 70),
        "is_suspicious": bool(31 <= risk_score < 70),
        "is_safe": bool(risk_score < 31),
        "phishing_probability": round(float(phishing_probability), 4),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "badge_class": badge_class,
        "confidence": confidence,
        "confidence_description": confidence_desc,
        "description": risk_desc,
        "critical_flags": critical_flags,
        "evidence_summary": evidence_summary,
        "synthesis": synthesis,
        "html_analysis_available": extraction_meta.get("html_analysis", False),
        "feature_completeness_pct": completeness_pct,
        "ood_info": ood_info
    }
