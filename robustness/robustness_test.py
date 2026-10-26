"""
Robustness evaluation test runner.
Runs the complete feature extraction and prediction pipeline on mutated variants.
"""
import sys
from pathlib import Path
from typing import Dict, List, Any
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from detection.predictor import PhishingPredictor
from detection.risk_score import calculate_risk_score, get_risk_level
from .url_mutations import UrlMutationGenerator

class RobustnessTester:
    """
    Executes controlled perturbation tests to evaluate model decision consistency.
    """
    def __init__(self):
        self.pipeline = FeatureExtractionPipeline(enable_live_html=False)
        self.predictor = PhishingPredictor()

    def run_robustness_test(self, original_url: str) -> Dict[str, Any]:
        """
        Tests the original URL against 5 controlled mutations.
        """
        # 1. Baseline analysis
        df_orig, _ = self.pipeline.extract_features(original_url)
        orig_pred, orig_prob, _, _ = self.predictor.predict(df_orig, is_html_live=False)
        orig_risk = calculate_risk_score(orig_prob)
        orig_level, orig_badge, _ = get_risk_level(orig_risk)

        original_summary = {
            "url": original_url,
            "prediction": "phishing" if orig_pred == 1 else "legitimate",
            "probability": round(float(orig_prob), 4),
            "risk_score": orig_risk,
            "risk_level": orig_level,
            "badge_class": orig_badge
        }

        # 2. Mutated variants
        mutations = UrlMutationGenerator.generate_all_mutations(original_url)
        variant_results = []
        consistent_count = 0
        risk_scores = [orig_risk]

        for mut in mutations:
            var_url = mut["url"]
            try:
                df_var, _ = self.pipeline.extract_features(var_url)
                v_pred, v_prob, _, _ = self.predictor.predict(df_var, is_html_live=False)
                v_risk = calculate_risk_score(v_prob)
                v_level, v_badge, _ = get_risk_level(v_risk)
                
                is_consistent = bool(v_pred == orig_pred)
                if is_consistent:
                    consistent_count += 1
                risk_scores.append(v_risk)

                variant_results.append({
                    "variant_name": mut["variant_name"],
                    "description": mut["description"],
                    "url": var_url,
                    "prediction": "phishing" if v_pred == 1 else "legitimate",
                    "probability": round(float(v_prob), 4),
                    "risk_score": v_risk,
                    "risk_level": v_level,
                    "badge_class": v_badge,
                    "is_consistent": is_consistent,
                    "risk_delta": v_risk - orig_risk
                })
            except Exception as e:
                variant_results.append({
                    "variant_name": mut["variant_name"],
                    "description": mut["description"],
                    "url": var_url,
                    "error": str(e),
                    "is_consistent": False
                })

        total_variants = len(variant_results)
        consistency_pct = (consistent_count / total_variants * 100.0) if total_variants > 0 else 0.0
        risk_std = float(np.std(risk_scores)) if risk_scores else 0.0
        max_delta = max([abs(r) for r in [v.get("risk_delta", 0) for v in variant_results]]) if variant_results else 0

        # Stability rating
        if consistency_pct >= 80 and risk_std <= 15:
            stability_grade = "HIGH STABILITY"
            stability_desc = "The model's decision remains robust across controlled URL perturbations."
        elif consistency_pct >= 60:
            stability_grade = "MODERATE STABILITY"
            stability_desc = "The model demonstrates reasonable stability with minor sensitivity to structural perturbations."
        else:
            stability_grade = "SENSITIVE TO PERTURBATIONS"
            stability_desc = "Noticeable decision variance detected across syntactic variations."

        return {
            "original": original_summary,
            "variants": variant_results,
            "summary": {
                "total_variants_tested": total_variants,
                "consistent_predictions": consistent_count,
                "consistency_percentage": round(consistency_pct, 1),
                "risk_score_std": round(risk_std, 2),
                "max_risk_delta": max_delta,
                "stability_grade": stability_grade,
                "stability_description": stability_desc
            },
            "disclaimer": "Controlled robustness evaluation measures decision stability under syntactic variations. It does not certify immunity to all adversarial attacks."
        }
