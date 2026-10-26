"""
REST API Blueprint providing programmatically accessible endpoints and developer diagnostics.
"""
import logging
from flask import Blueprint, request, jsonify

from api.schemas import validate_url_request, validate_feedback_request
from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from detection.predictor import PhishingPredictor
from detection.decision_engine import evaluate_decision
from detection.result_formatter import format_analysis_result
from explainability.explanation_generator import ExplanationGenerator
from robustness.robustness_test import RobustnessTester
from feedback.feedback_manager import FeedbackManager

logger = logging.getLogger("phishguard.api")
api_bp = Blueprint("api", __name__, url_prefix="/api")

# Lazy-loaded singletons
_pipeline = None
_predictor = None
_explainer_gen = None
_robustness_tester = None
_feedback_mgr = None
_analysis_history = []

def get_services():
    global _pipeline, _predictor, _explainer_gen, _robustness_tester, _feedback_mgr
    if _pipeline is None:
        _pipeline = FeatureExtractionPipeline(enable_live_html=True)
    if _predictor is None:
        _predictor = PhishingPredictor()
    if _explainer_gen is None:
        _explainer_gen = ExplanationGenerator()
    if _robustness_tester is None:
        _robustness_tester = RobustnessTester()
    if _feedback_mgr is None:
        _feedback_mgr = FeedbackManager()
    return _pipeline, _predictor, _explainer_gen, _robustness_tester, _feedback_mgr

@api_bp.route("/analyze", methods=["POST"])
def analyze_url():
    """
    POST /api/analyze
    Analyzes a URL and returns complete security diagnosis and explanations.
    """
    data = request.get_json(silent=True)
    url_str, err = validate_url_request(data)
    if err:
        return jsonify({"status": "error", "error": err}), 400

    try:
        pipeline, predictor, explainer_gen, _, _ = get_services()
        
        # 1. Feature Extraction
        df_features, extract_meta = pipeline.extract_features(url_str)
        
        # 2. Adaptive Prediction with Dynamic Class Mapping & Calibration
        pred, prob, prob_dict, diag_meta = predictor.predict(
            df_features,
            is_html_live=extract_meta.get("html_analysis", False)
        )
        
        # 3. Decision Matrix with Evidence Synthesis
        decision = evaluate_decision(pred, prob, df_features, extract_meta, diag_meta)
        
        # 4. Explainable AI
        explanation = explainer_gen.generate_explanation(df_features, decision["is_phishing"])
        
        # 5. Format Result
        result = format_analysis_result(
            url=url_str,
            df_features=df_features,
            decision_info=decision,
            explanation_info=explanation,
            extraction_meta=extract_meta,
            model_metadata=predictor.metadata,
            diag_meta=diag_meta
        )
        
        # Record into history (capped at 100 entries)
        _analysis_history.insert(0, {
            "url": url_str,
            "timestamp": result["timestamp"],
            "prediction": result["prediction"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "badge_class": result["badge_class"]
        })
        if len(_analysis_history) > 100:
            _analysis_history.pop()

        return jsonify({"status": "success", "data": result}), 200

    except Exception as e:
        logger.error(f"Analysis error on URL '{url_str}': {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "error": "An error occurred while analyzing the target URL. Please verify the URL and try again."
        }), 500

@api_bp.route("/diagnostic", methods=["POST"])
def get_diagnostics():
    """
    POST /api/diagnostic
    Developer diagnostic mode: outputs raw feature vectors, OOD flags, calibration telemetry,
    and granular evidence summaries for troubleshooting classification edge cases.
    """
    data = request.get_json(silent=True)
    url_str, err = validate_url_request(data)
    if err:
        return jsonify({"status": "error", "error": err}), 400

    try:
        pipeline, predictor, explainer_gen, _, _ = get_services()
        df_features, extract_meta = pipeline.extract_features(url_str)
        pred, prob, prob_dict, diag_meta = predictor.predict(
            df_features,
            is_html_live=extract_meta.get("html_analysis", False)
        )
        decision = evaluate_decision(pred, prob, df_features, extract_meta, diag_meta)
        explanation = explainer_gen.generate_explanation(df_features, decision["is_phishing"])
        
        return jsonify({
            "status": "success",
            "diagnostic_report": {
                "target_url": url_str,
                "model_prediction": "phishing" if pred == 1 else "legitimate",
                "calibrated_phishing_probability": round(prob, 4),
                "probabilities": prob_dict,
                "risk_score": decision["risk_score"],
                "risk_level": decision["risk_level"],
                "final_verdict": decision["verdict"],
                "confidence": decision["confidence"],
                "confidence_description": decision.get("confidence_description"),
                "pipeline_mode": diag_meta.get("pipeline_mode"),
                "feature_completeness": f"{extract_meta.get('features_extracted_count', 48)}/{extract_meta.get('total_features_count', 48)} ({extract_meta.get('feature_completeness_pct', 100)}%)",
                "out_of_distribution": diag_meta.get("ood_info", {}),
                "url_evidence": decision.get("evidence_summary", {}).get("url_evidence", []),
                "domain_evidence": decision.get("evidence_summary", {}).get("domain_evidence", []),
                "html_evidence": decision.get("evidence_summary", {}).get("html_evidence", []),
                "critical_security_flags": decision.get("critical_flags", []),
                "top_shap_factors": explanation.get("technical_factors", [])[:6]
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@api_bp.route("/robustness-test", methods=["POST"])
def test_robustness():
    """
    POST /api/robustness-test
    Executes controlled perturbation suite on target URL.
    """
    data = request.get_json(silent=True)
    url_str, err = validate_url_request(data)
    if err:
        return jsonify({"status": "error", "error": err}), 400

    try:
        _, _, _, robustness_tester, _ = get_services()
        report = robustness_tester.run_robustness_test(url_str)
        return jsonify({"status": "success", "data": report}), 200
    except Exception as e:
        logger.error(f"Robustness test error on URL '{url_str}': {str(e)}", exc_info=True)
        return jsonify({"status": "error", "error": f"Failed to execute robustness evaluation: {str(e)}"}), 500

@api_bp.route("/feedback", methods=["POST"])
def submit_feedback():
    """
    POST /api/feedback
    Receives and logs user feedback for continuous improvement.
    """
    data = request.get_json(silent=True)
    payload, err = validate_feedback_request(data)
    if err:
        return jsonify({"status": "error", "error": err}), 400

    try:
        _, _, _, _, feedback_mgr = get_services()
        entry = feedback_mgr.record_feedback(
            url=payload["url"],
            predicted_label=payload["predicted_label"],
            probability=payload["probability"],
            risk_score=payload["risk_score"],
            user_feedback=payload["user_feedback"],
            actual_label=payload.get("actual_label"),
            comments=payload.get("comments", "")
        )
        return jsonify({"status": "success", "message": "Feedback recorded successfully.", "entry": entry}), 200
    except Exception as e:
        logger.error(f"Feedback storage error: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "error": f"Failed to record feedback: {str(e)}"}), 500

@api_bp.route("/history", methods=["GET"])
def get_history():
    """
    GET /api/history
    Returns recent analysis logs.
    """
    return jsonify({"status": "success", "history": _analysis_history}), 200

@api_bp.route("/model-info", methods=["GET"])
def get_model_info():
    """
    GET /api/model-info
    Returns live metadata, accuracy, precision, recall, and top features.
    """
    try:
        _, predictor, _, _, feedback_mgr = get_services()
        meta = predictor.metadata
        fb_stats = feedback_mgr.get_summary_stats()
        
        return jsonify({
            "status": "success",
            "model_metadata": meta,
            "feedback_statistics": fb_stats
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
