"""
Enhanced Result serialization and presentation formatter.
Compiles comprehensive security reports with structured evidence summaries,
feature completeness metrics, OOD warnings, and confidence grades.
"""
import datetime
from typing import Dict, Any
import pandas as pd

def format_analysis_result(
    url: str,
    df_features: pd.DataFrame,
    decision_info: Dict[str, Any],
    explanation_info: Dict[str, Any],
    extraction_meta: Dict[str, Any],
    model_metadata: Dict[str, Any],
    diag_meta: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Compiles the complete analysis report for UI rendering, developer diagnostics, and REST API response.
    """
    if diag_meta is None:
        diag_meta = {}
        
    feat_dict = {col: round(float(df_features[col].values[0]), 4) for col in df_features.columns}
    completeness_pct = extraction_meta.get("feature_completeness_pct", 100.0)
    ood_info = diag_meta.get("ood_info", {})
    
    return {
        "url": url,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "verdict": decision_info["verdict"],
        "verdict_summary": decision_info.get("verdict_summary", ""),
        "prediction": "phishing" if decision_info["is_phishing"] else ("suspicious" if decision_info.get("is_suspicious") else "legitimate"),
        "risk_score": decision_info["risk_score"],
        "risk_level": decision_info["risk_level"],
        "badge_class": decision_info["badge_class"],
        "probability": decision_info["phishing_probability"],
        "confidence": decision_info["confidence"],
        "confidence_description": decision_info.get("confidence_description", ""),
        "summary_description": decision_info["description"],
        "critical_flags": decision_info["critical_flags"],
        "evidence_summary": decision_info.get("evidence_summary", {}),
        "data_quality": {
            "feature_completeness": f"{extraction_meta.get('features_extracted_count', 48)}/{extraction_meta.get('total_features_count', 48)} ({completeness_pct}%)",
            "feature_completeness_pct": completeness_pct,
            "pipeline_mode": diag_meta.get("pipeline_mode", "Adaptive Hybrid"),
            "is_out_of_distribution": ood_info.get("is_ood", False),
            "ood_warning": ood_info.get("warning"),
            "anomalous_features": ood_info.get("anomalous_features", [])
        },
        "analysis_status": {
            "url_features": extraction_meta.get("url_analysis", True),
            "domain_features": extraction_meta.get("domain_analysis", True),
            "html_features": extraction_meta.get("html_analysis", False),
            "html_message": extraction_meta.get("html_message", ""),
            "mode": extraction_meta.get("mode", "url_only")
        },
        "domain_metadata": extraction_meta.get("domain_metadata", {}),
        "explanation": explanation_info,
        "features": feat_dict,
        "model_info": {
            "name": model_metadata.get("model_name", "Calibrated Adaptive XGBoost"),
            "algorithm": model_metadata.get("algorithm_class", "CalibratedClassifierCV(XGBClassifier)"),
            "accuracy": model_metadata.get("metrics", {}).get("accuracy", 0.988),
            "features_count": len(df_features.columns)
        },
        "disclaimer": "This analysis describes the model's reasoning based on extracted structural and content features. It is an academic research prototype and does not provide an absolute guarantee of website safety."
    }
