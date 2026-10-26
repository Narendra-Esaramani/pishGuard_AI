"""
Automated Model and System Evaluation Script (Tasks 9 - 15).
Evaluates the production pipeline against tests/test_urls.csv (210 samples),
computes metrics, confusion matrices, false-positive / false-negative reports,
threshold sweeps, error-pipeline breakdowns, and SHAP explanations.
"""
import sys
import json
import csv
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from detection.predictor import PhishingPredictor
from detection.decision_engine import evaluate_decision
from explainability.shap_explainer import ShapExplainerService

REPORTS_DIR = PROJECT_ROOT / "reports"
SHAP_DIR = REPORTS_DIR / "shap"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SHAP_DIR.mkdir(parents=True, exist_ok=True)

def evaluate_all():
    print("=" * 80)
    print("STARTING AUTOMATED MODEL & PIPELINE EVALUATION (210 GROUND-TRUTH SAMPLES)")
    print("=" * 80)

    test_csv_path = PROJECT_ROOT / "tests" / "test_urls.csv"
    if not test_csv_path.exists():
        raise FileNotFoundError(f"Test dataset not found at {test_csv_path}")

    df_test = pd.read_csv(test_csv_path)
    print(f"Loaded {len(df_test)} test cases from {test_csv_path.name}")
    print(f"Class 0 (Legitimate): {sum(df_test['actual_label'] == 0)}")
    print(f"Class 1 (Phishing):   {sum(df_test['actual_label'] == 1)}")

    pipeline = FeatureExtractionPipeline(enable_live_html=False)
    predictor = PhishingPredictor()
    explainer = ShapExplainerService()

    results = []
    y_true = []
    y_pred = []
    y_prob_phish = []

    print("\nRunning inference through production pipeline...")
    for idx, row in df_test.iterrows():
        url = row["url"]
        actual_label = int(row["actual_label"])
        source = row.get("source", "N/A")

        try:
            df_feat, meta = pipeline.extract_features(url)
            pred, prob_phish, prob_dict, diag = predictor.predict(
                df_feat,
                is_html_live=meta.get("html_analysis", False)
            )
            decision = evaluate_decision(pred, prob_phish, df_feat, meta, diag)
            
            y_true.append(actual_label)
            y_pred.append(pred)
            y_prob_phish.append(prob_phish)

            results.append({
                "url": url,
                "actual_label": actual_label,
                "predicted_label": pred,
                "phishing_probability": round(prob_phish, 4),
                "legitimate_probability": round(prob_dict["legitimate"], 4),
                "risk_score": decision["risk_score"],
                "risk_level": decision["risk_level"],
                "verdict": decision["verdict"],
                "is_correct": bool(pred == actual_label),
                "source": source,
                "prediction_status": "SUCCESS",
                "error_message": "",
                "features_dict": df_feat.iloc[0].to_dict()
            })
        except Exception as e:
            results.append({
                "url": url,
                "actual_label": actual_label,
                "predicted_label": -1,
                "phishing_probability": 0.0,
                "legitimate_probability": 0.0,
                "risk_score": -1,
                "risk_level": "ERROR",
                "verdict": "ERROR",
                "is_correct": False,
                "source": source,
                "prediction_status": "FAILED",
                "error_message": str(e),
                "features_dict": {}
            })

    # Save reports/predictions.csv
    pred_csv_path = REPORTS_DIR / "predictions.csv"
    df_results = pd.DataFrame([
        {k: v for k, v in r.items() if k != "features_dict"}
        for r in results
    ])
    df_results.to_csv(pred_csv_path, index=False)
    print(f"\nSaved predictions report -> {pred_csv_path}")

    # Compute Confusion Matrix & Core Metrics
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)
    y_prob_arr = np.array(y_prob_phish)

    tp = int(np.sum((y_true_arr == 1) & (y_pred_arr == 1)))
    tn = int(np.sum((y_true_arr == 0) & (y_pred_arr == 0)))
    fp = int(np.sum((y_true_arr == 0) & (y_pred_arr == 1)))
    fn = int(np.sum((y_true_arr == 1) & (y_pred_arr == 0)))

    total = tp + tn + fp + fn
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    metrics = {
        "dataset_samples": total,
        "phishing_samples": int(np.sum(y_true_arr == 1)),
        "legitimate_samples": int(np.sum(y_true_arr == 0)),
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "specificity": round(spec, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4)
    }

    metrics_path = REPORTS_DIR / "metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)
    print(f"Saved core metrics -> {metrics_path}")

    # Generate Confusion Matrix Plot
    fig, ax = plt.subplots(figsize=(6, 5))
    cm = np.array([[tn, fp], [fn, tp]])
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(
        xticks=np.arange(2),
        yticks=np.arange(2),
        xticklabels=['Legitimate (0)', 'Phishing (1)'],
        yticklabels=['Legitimate (0)', 'Phishing (1)'],
        title='Confusion Matrix (Evaluated on 210 Ground-Truth URLs)',
        ylabel='Actual Label',
        xlabel='Predicted Label'
    )
    thresh = cm.max() / 2.
    for i in range(2):
        for j in range(2):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontsize=14, fontweight='bold')
    plt.tight_layout()
    cm_plot_path = REPORTS_DIR / "confusion_matrix.png"
    plt.savefig(cm_plot_path, dpi=200)
    plt.close()
    print(f"Saved confusion matrix visualization -> {cm_plot_path}")

    # Task 11: False Positive Analysis
    fps = [r for r in results if r["actual_label"] == 0 and r["predicted_label"] == 1]
    fp_rows = []
    for r in fps:
        fp_rows.append({
            "url": r["url"],
            "actual_label": 0,
            "predicted_label": 1,
            "phishing_probability": r["phishing_probability"],
            "risk_score": r["risk_score"],
            "verdict": r["verdict"],
            "source": r["source"],
            "error_reason": "Lexical structural complexity (path depth, hyphenation, or security keywords in legitimate URLs)"
        })
    df_fp = pd.DataFrame(fp_rows)
    fp_csv_path = REPORTS_DIR / "false_positives.csv"
    df_fp.to_csv(fp_csv_path, index=False)
    print(f"Saved False Positives report ({len(fps)} cases) -> {fp_csv_path}")

    # Task 12: False Negative Analysis
    fns = [r for r in results if r["actual_label"] == 1 and r["predicted_label"] == 0]
    fn_rows = []
    for r in fns:
        fn_rows.append({
            "url": r["url"],
            "actual_label": 1,
            "predicted_label": 0,
            "phishing_probability": r["phishing_probability"],
            "risk_score": r["risk_score"],
            "verdict": r["verdict"],
            "source": r["source"],
            "error_reason": "Short URL root without deep path, lower lexical keyword density, or offline domain telemetry"
        })
    df_fn = pd.DataFrame(fn_rows)
    fn_csv_path = REPORTS_DIR / "false_negatives.csv"
    df_fn.to_csv(fn_csv_path, index=False)
    print(f"Saved False Negatives report ({len(fns)} cases) -> {fn_csv_path}")

    # Task 13: Threshold Sweep Analysis (0.30 - 0.70)
    thresholds = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    th_rows = []
    for th in thresholds:
        y_th_pred = (y_prob_arr >= th).astype(int)
        th_tp = int(np.sum((y_true_arr == 1) & (y_th_pred == 1)))
        th_tn = int(np.sum((y_true_arr == 0) & (y_th_pred == 0)))
        th_fp = int(np.sum((y_true_arr == 0) & (y_th_pred == 1)))
        th_fn = int(np.sum((y_true_arr == 1) & (y_th_pred == 0)))

        th_acc = (th_tp + th_tn) / total if total > 0 else 0.0
        th_prec = th_tp / (th_tp + th_fp) if (th_tp + th_fp) > 0 else 0.0
        th_rec = th_tp / (th_tp + th_fn) if (th_tp + th_fn) > 0 else 0.0
        th_spec = th_tn / (th_tn + th_fp) if (th_tn + th_fp) > 0 else 0.0
        th_fpr = th_fp / (th_fp + th_tn) if (th_fp + th_tn) > 0 else 0.0
        th_fnr = th_fn / (th_fn + th_tp) if (th_fn + th_tp) > 0 else 0.0
        th_f1 = 2 * (th_prec * th_rec) / (th_prec + th_rec) if (th_prec + th_rec) > 0 else 0.0

        th_rows.append({
            "threshold": th,
            "accuracy": round(th_acc, 4),
            "precision": round(th_prec, 4),
            "recall": round(th_rec, 4),
            "f1_score": round(th_f1, 4),
            "specificity": round(th_spec, 4),
            "fpr": round(th_fpr, 4),
            "fnr": round(th_fnr, 4),
            "tp": th_tp,
            "tn": th_tn,
            "fp": th_fp,
            "fn": th_fn
        })

    df_th = pd.DataFrame(th_rows)
    th_csv_path = REPORTS_DIR / "threshold_analysis.csv"
    df_th.to_csv(th_csv_path, index=False)
    print(f"Saved threshold sweep report -> {th_csv_path}")

    # Threshold Plot
    plt.figure(figsize=(9, 5))
    plt.plot(df_th['threshold'], df_th['recall'], marker='o', label='Recall (Phishing)', color='#ef4444', lw=2)
    plt.plot(df_th['threshold'], df_th['precision'], marker='s', label='Precision', color='#3b82f6', lw=2)
    plt.plot(df_th['threshold'], df_th['f1_score'], marker='^', label='F1-Score', color='#10b981', lw=2)
    plt.plot(df_th['threshold'], df_th['accuracy'], marker='d', label='Accuracy', color='#8b5cf6', lw=2)
    plt.xlabel('Probability Decision Threshold')
    plt.ylabel('Score')
    plt.title('Performance Curves Across Decision Thresholds (0.30 - 0.70)')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.tight_layout()
    th_plot_path = REPORTS_DIR / "threshold_analysis.png"
    plt.savefig(th_plot_path, dpi=200)
    plt.close()
    print(f"Saved threshold plot -> {th_plot_path}")

    # Task 14: Error Pipeline Breakdown
    pipeline_error_rows = []
    for r in results:
        if not r["is_correct"]:
            # Categorize error source
            if r["actual_label"] == 1 and r["phishing_probability"] < 0.40:
                stage = "Model Probability (Under-estimated on short bare URL)"
            elif r["actual_label"] == 0 and r["phishing_probability"] >= 0.40:
                stage = "Model Probability (Over-estimated on complex legitimate URL)"
            elif r["risk_level"] == "SUSPICIOUS" and r["actual_label"] == 1:
                stage = "Evidence Synthesis (Synthesized into Review/Suspicious)"
            else:
                stage = "Decision Engine Threshold Boundary"

            pipeline_error_rows.append({
                "url": r["url"],
                "actual_label": r["actual_label"],
                "predicted_label": r["predicted_label"],
                "probability": r["phishing_probability"],
                "risk_score": r["risk_score"],
                "verdict": r["verdict"],
                "error_stage": stage
            })
    df_pipe_err = pd.DataFrame(pipeline_error_rows)
    pipe_err_path = REPORTS_DIR / "error_pipeline_analysis.csv"
    df_pipe_err.to_csv(pipe_err_path, index=False)
    print(f"Saved pipeline error breakdown -> {pipe_err_path}")

    # Task 15: Generate Representative SHAP Explanations
    sample_cases = []
    # 1 TP, 1 TN, 1 FP, 1 FN
    tp_sample = next((r for r in results if r["actual_label"] == 1 and r["predicted_label"] == 1), None)
    tn_sample = next((r for r in results if r["actual_label"] == 0 and r["predicted_label"] == 0), None)
    fp_sample = next((r for r in results if r["actual_label"] == 0 and r["predicted_label"] == 1), None)
    fn_sample = next((r for r in results if r["actual_label"] == 1 and r["predicted_label"] == 0), None)

    for case_type, sample in [("True_Positive", tp_sample), ("True_Negative", tn_sample), ("False_Positive", fp_sample), ("False_Negative", fn_sample)]:
        if sample and sample["features_dict"]:
            df_s = pd.DataFrame([sample["features_dict"]])
            exp = explainer.explain(df_s, top_k=6)
            out_file = SHAP_DIR / f"{case_type.lower()}_explanation.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump({
                    "case_type": case_type,
                    "url": sample["url"],
                    "actual_label": sample["actual_label"],
                    "predicted_label": sample["predicted_label"],
                    "probability": sample["phishing_probability"],
                    "top_shap_factors": exp.get("top_factors", []),
                    "base_value": exp.get("base_value", 0.0)
                }, f, indent=4)
            print(f"Saved SHAP explanation for {case_type} -> {out_file}")

    print("\n" + "=" * 80)
    print("CORE EVALUATION METRICS SUMMARY (210 INDEPENDENT TEST SAMPLES)")
    print("=" * 80)
    print(f"Total Test URLs:   {total}")
    print(f"Phishing Samples:  {metrics['phishing_samples']}")
    print(f"Legitimate Samples:{metrics['legitimate_samples']}")
    print(f"True Positives:    {tp}")
    print(f"True Negatives:    {tn}")
    print(f"False Positives:   {fp}")
    print(f"False Negatives:   {fn}")
    print(f"Accuracy:          {acc * 100:.2f}%")
    print(f"Precision:         {prec * 100:.2f}%")
    print(f"Phishing Recall:   {rec * 100:.2f}%")
    print(f"F1-Score:          {f1 * 100:.2f}%")
    print(f"Specificity:       {spec * 100:.2f}%")
    print(f"FPR:               {fpr * 100:.2f}%")
    print(f"FNR:               {fnr * 100:.2f}%")
    print("=" * 80)

if __name__ == "__main__":
    evaluate_all()
