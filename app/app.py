"""
Flask Application Factory and Web View Handlers.
"""
import os
import sys
import logging
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import SECRET_KEY, DEBUG
from api.routes import api_bp, get_services, _analysis_history
from detection.decision_engine import evaluate_decision
from detection.result_formatter import format_analysis_result

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishguard.app")

def create_app():
    """Initializes and configures the Flask application."""
    app = Flask(
        __name__,
        template_folder=str(PROJECT_ROOT / "app" / "templates"),
        static_folder=str(PROJECT_ROOT / "app" / "static")
    )
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DEBUG"] = DEBUG

    # Register API Blueprint
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/analyze", methods=["POST"])
    def analyze_web():
        url = request.form.get("url", "").strip()
        if not url:
            flash("Please enter a valid website URL to analyze.", "warning")
            return redirect(url_for("index"))
            
        try:
            pipeline, predictor, explainer_gen, _, _ = get_services()
            
            # 1. Feature extraction
            df_features, extract_meta = pipeline.extract_features(url)
            
            # 2. Adaptive Calibrated Prediction
            pred, prob, prob_dict, diag_meta = predictor.predict(
                df_features,
                is_html_live=extract_meta.get("html_analysis", False)
            )
            
            # 3. Decision Matrix
            decision = evaluate_decision(pred, prob, df_features, extract_meta, diag_meta)
            
            # 4. Explainable AI
            explanation = explainer_gen.generate_explanation(df_features, decision["is_phishing"])
            
            # 5. Format Result
            result = format_analysis_result(
                url=url,
                df_features=df_features,
                decision_info=decision,
                explanation_info=explanation,
                extraction_meta=extract_meta,
                model_metadata=predictor.metadata,
                diag_meta=diag_meta
            )
            
            # Save in history
            _analysis_history.insert(0, {
                "url": url,
                "timestamp": result["timestamp"],
                "prediction": result["prediction"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "badge_class": result["badge_class"]
            })
            if len(_analysis_history) > 100:
                _analysis_history.pop()
                
            return render_template("result.html", report=result)
            
        except Exception as e:
            logger.error(f"Web analysis error on '{url}': {str(e)}", exc_info=True)
            flash(f"Error analyzing URL: {str(e)}", "danger")
            return redirect(url_for("index"))

    @app.route("/history")
    def history():
        return render_template("history.html", history=_analysis_history)

    @app.route("/model-info")
    def model_info():
        _, predictor, _, _, feedback_mgr = get_services()
        meta = predictor.metadata
        fb_stats = feedback_mgr.get_summary_stats()
        return render_template("model_info.html", metadata=meta, feedback_stats=fb_stats)

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("base.html", error_title="404 Not Found", error_msg="The requested page does not exist."), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template("base.html", error_title="500 Internal Server Error", error_msg="An unexpected error occurred. Please try again."), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
