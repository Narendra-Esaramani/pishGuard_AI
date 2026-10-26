"""
Experimental Evaluation Script (Tasks 5, 7, 8).
Splits test_urls.csv into:
- Validation Set (100 URLs: 50 legit, 50 phish) to tune decision threshold (0.50, 0.60, 0.65, 0.70)
- Held-Out Test Set (110 URLs: 55 legit, 55 phish) for final unbiased evaluation of Baseline vs Experimental.
Saves all artifacts to reports/experimental/
"""
import sys
import json
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import brier_score_loss

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from detection.predictor import PhishingPredictor
from detection.decision_engine import evaluate_decision

EXP_REPORTS_DIR = PROJECT_ROOT / "reports" / "experimental"
EXP_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def run_evaluation():
    print("=" * 80)
    print("STARTING EXPERIMENTAL PIPELINE EVALUATION (VALIDATION SPLIT + HELD-OUT TEST)")
    print("=" * 80)

    test_csv_path = PROJECT_ROOT / "tests" / "test_urls.csv"
    df_all = pd.read_csv(test_csv_path)

    # Deterministic train/validation/test split
    # 50 legit + 50 phish -> Validation (100 samples)
    # 55 legit + 55 phish -> Held-Out Test (110 samples)
    df_legit = df_all[df_all["actual_label"] == 0].reset_index(drop=True)
    df_phish = df_all[df_all["actual_label"] == 1].reset_index(drop=True)

    val_legit = df_legit.iloc[:50]
    test_legit = df_legit.iloc[50:]

    val_phish = df_phish.iloc[:50]
    test_phish = df_phish.iloc[50:]

    df_val = pd.concat([val_legit, val_phish]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    df_test = pd.concat([test_legit, test_phish]).sample(frac=1.0, random_state=42).reset_index(drop=True)

    print(f"Validation Set Size: {len(df_val)} (Legit: {sum(df_val['actual_label']==0)}, Phish: {sum(df_val['actual_label']==1)})")
    print(f"Held-Out Test Size:  {len(df_test)} (Legit: {sum(df_test['actual_label']==0)}, Phish: {sum(df_test['actual_label']==1)})")

    pipeline = FeatureExtractionPipeline(enable_live_html=False)
    predictor = PhishingPredictor()

    # STEP 1: Evaluate Candidate Thresholds on Validation Set
    print("\n--- STEP 1: THRESHOLD SWEEP ON VALIDATION SET (0.50, 0.60, 0.65, 0.70) ---")
    val_probs = []
    val_true = []
    val_records = []

    for idx, row in df_val.iterrows():
        url = row["url"]
        actual = int(row["actual_label"])
        df_feat, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)
        val_probs.append(prob)
        val_true.append(actual)
        val_records.append((url, actual, df_feat, meta, diag, pred, prob))

    val_probs_arr = np.array(val_probs)
    val_true_arr = np.array(val_true)

    th_candidates = [0.50, 0.60, 0.65, 0.70]
    th_val_results = []

    for th in th_candidates:
        # Evaluate Experimental Synthesis on Validation Set with threshold th
        preds_exp = []
        for url, actual, df_feat, meta, diag, pred, prob in val_records:
            dec = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True, decision_threshold=th)
            # Binary prediction from verdict: LIKELY PHISHING -> 1, SAFE/SUSPICIOUS -> 0
            p_bin = 1 if dec["verdict"] == "LIKELY PHISHING" else 0
            preds_exp.append(p_bin)
            
        preds_exp_arr = np.array(preds_exp)
        tp = int(np.sum((val_true_arr == 1) & (preds_exp_arr == 1)))
        tn = int(np.sum((val_true_arr == 0) & (preds_exp_arr == 0)))
        fp = int(np.sum((val_true_arr == 0) & (preds_exp_arr == 1)))
        fn = int(np.sum((val_true_arr == 1) & (preds_exp_arr == 0)))

        acc = (tp + tn) / len(val_true_arr)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        th_val_results.append({
            "threshold": th,
            "validation_accuracy": round(acc * 100, 2),
            "validation_precision": round(prec * 100, 2),
            "validation_recall": round(rec * 100, 2),
            "validation_f1": round(f1 * 100, 2),
            "validation_specificity": round(spec * 100, 2),
            "validation_fpr": round(fpr * 100, 2),
            "validation_fnr": round(fnr * 100, 2),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn
        })

    df_th_val = pd.DataFrame(th_val_results)
    th_val_path = EXP_REPORTS_DIR / "threshold_validation_sweep.csv"
    df_th_val.to_csv(th_val_path, index=False)
    print(df_th_val.to_string(index=False))
    print(f"Saved validation sweep report -> {th_val_path}")

    # Optimal threshold from validation split (best F1 score & low FPR)
    best_row = df_th_val.sort_values(by=["validation_f1", "validation_recall"], ascending=False).iloc[0]
    optimal_th = float(best_row["threshold"])
    print(f"\n>>> Selected Optimal Threshold based on Validation Split: {optimal_th} (Val F1: {best_row['validation_f1']}%) <<<")

    # STEP 2: Evaluate on Untouched Held-Out Test Set (110 Samples)
    print("\n--- STEP 2: EVALUATING BASELINE VS EXPERIMENTAL ON HELD-OUT TEST SET (110 SAMPLES) ---")
    baseline_preds = []
    exp_preds = []
    test_true = []
    test_probs = []
    exp_details = []

    for idx, row in df_test.iterrows():
        url = row["url"]
        actual = int(row["actual_label"])
        df_feat, meta = pipeline.extract_features(url)
        pred, prob, prob_dict, diag = predictor.predict(df_feat, is_html_live=False)

        # 1. Baseline Evaluation
        base_dec = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=False)
        base_bin = 1 if base_dec["verdict"] == "LIKELY PHISHING" else (1 if prob >= 0.50 else 0)

        # 2. Experimental Evaluation with optimal_th
        exp_dec = evaluate_decision(pred, prob, df_feat, meta, diag, use_experimental=True, decision_threshold=optimal_th)
        exp_bin = 1 if exp_dec["verdict"] == "LIKELY PHISHING" else 0

        test_true.append(actual)
        test_probs.append(prob)
        baseline_preds.append(base_bin)
        exp_preds.append(exp_bin)

        exp_details.append({
            "url": url,
            "actual_label": actual,
            "baseline_predicted": base_bin,
            "experimental_predicted": exp_bin,
            "phishing_probability": round(prob, 4),
            "baseline_verdict": base_dec["verdict"],
            "experimental_verdict": exp_dec["verdict"],
            "baseline_risk_score": base_dec["risk_score"],
            "experimental_risk_score": exp_dec["risk_score"],
            "experimental_badge": exp_dec["badge_class"],
            "is_experimental_correct": bool(exp_bin == actual)
        })

    test_true_arr = np.array(test_true)
    base_preds_arr = np.array(baseline_preds)
    exp_preds_arr = np.array(exp_preds)
    test_probs_arr = np.array(test_probs)

    # Compute metrics for baseline
    b_tp = int(np.sum((test_true_arr == 1) & (base_preds_arr == 1)))
    b_tn = int(np.sum((test_true_arr == 0) & (base_preds_arr == 0)))
    b_fp = int(np.sum((test_true_arr == 0) & (base_preds_arr == 1)))
    b_fn = int(np.sum((test_true_arr == 1) & (base_preds_arr == 0)))

    b_acc = (b_tp + b_tn) / len(test_true_arr)
    b_prec = b_tp / (b_tp + b_fp) if (b_tp + b_fp) > 0 else 0.0
    b_rec = b_tp / (b_tp + b_fn) if (b_tp + b_fn) > 0 else 0.0
    b_spec = b_tn / (b_tn + b_fp) if (b_tn + b_fp) > 0 else 0.0
    b_f1 = 2 * b_prec * b_rec / (b_prec + b_rec) if (b_prec + b_rec) > 0 else 0.0
    b_fpr = b_fp / (b_fp + b_tn) if (b_fp + b_tn) > 0 else 0.0
    b_fnr = b_fn / (b_fn + b_tp) if (b_fn + b_tp) > 0 else 0.0

    # Compute metrics for experimental
    e_tp = int(np.sum((test_true_arr == 1) & (exp_preds_arr == 1)))
    e_tn = int(np.sum((test_true_arr == 0) & (exp_preds_arr == 0)))
    e_fp = int(np.sum((test_true_arr == 0) & (exp_preds_arr == 1)))
    e_fn = int(np.sum((test_true_arr == 1) & (exp_preds_arr == 0)))

    e_acc = (e_tp + e_tn) / len(test_true_arr)
    e_prec = e_tp / (e_tp + e_fp) if (e_tp + e_fp) > 0 else 0.0
    e_rec = e_tp / (e_tp + e_fn) if (e_tp + e_fn) > 0 else 0.0
    e_spec = e_tn / (e_tn + e_fp) if (e_tn + e_fp) > 0 else 0.0
    e_f1 = 2 * e_prec * e_rec / (e_prec + e_rec) if (e_prec + e_rec) > 0 else 0.0
    e_fpr = e_fp / (e_fp + e_tn) if (e_fp + e_tn) > 0 else 0.0
    e_fnr = e_fn / (e_fn + e_tp) if (e_fn + e_tp) > 0 else 0.0
    brier = brier_score_loss(test_true_arr, test_probs_arr)

    comparison_metrics = {
        "held_out_test_samples": len(test_true_arr),
        "optimal_threshold_used": optimal_th,
        "brier_score_loss": round(brier, 4),
        "baseline": {
            "tp": b_tp, "tn": b_tn, "fp": b_fp, "fn": b_fn,
            "accuracy": round(b_acc * 100, 2),
            "precision": round(b_prec * 100, 2),
            "recall": round(b_rec * 100, 2),
            "specificity": round(b_spec * 100, 2),
            "f1_score": round(b_f1 * 100, 2),
            "fpr": round(b_fpr * 100, 2),
            "fnr": round(b_fnr * 100, 2)
        },
        "experimental": {
            "tp": e_tp, "tn": e_tn, "fp": e_fp, "fn": e_fn,
            "accuracy": round(e_acc * 100, 2),
            "precision": round(e_prec * 100, 2),
            "recall": round(e_rec * 100, 2),
            "specificity": round(e_spec * 100, 2),
            "f1_score": round(e_f1 * 100, 2),
            "fpr": round(e_fpr * 100, 2),
            "fnr": round(e_fnr * 100, 2)
        },
        "delta": {
            "false_positives": e_fp - b_fp,
            "false_negatives": e_fn - b_fn,
            "accuracy_change": round((e_acc - b_acc) * 100, 2),
            "f1_change": round((e_f1 - b_f1) * 100, 2),
            "fpr_reduction": round((b_fpr - e_fpr) * 100, 2)
        }
    }

    metrics_out = EXP_REPORTS_DIR / "baseline_vs_experimental_test_metrics.json"
    with open(metrics_out, "w", encoding="utf-8") as f:
        json.dump(comparison_metrics, f, indent=4)
    print(f"\nSaved comparison metrics -> {metrics_out}")

    # Save detailed predictions CSV
    df_exp_det = pd.DataFrame(exp_details)
    preds_out = EXP_REPORTS_DIR / "experimental_predictions.csv"
    df_exp_det.to_csv(preds_out, index=False)
    print(f"Saved experimental predictions -> {preds_out}")

    # Save False Positives & False Negatives
    df_exp_fp = df_exp_det[(df_exp_det["actual_label"] == 0) & (df_exp_det["experimental_predicted"] == 1)]
    df_exp_fn = df_exp_det[(df_exp_det["actual_label"] == 1) & (df_exp_det["experimental_predicted"] == 0)]
    df_exp_fp.to_csv(EXP_REPORTS_DIR / "experimental_false_positives.csv", index=False)
    df_exp_fn.to_csv(EXP_REPORTS_DIR / "experimental_false_negatives.csv", index=False)

    # Plot Confusion Matrix Comparison
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))

    # Baseline CM
    cm_b = np.array([[b_tn, b_fp], [b_fn, b_tp]])
    im0 = axes[0].imshow(cm_b, interpolation="nearest", cmap=plt.cm.Blues)
    axes[0].set(xticks=[0, 1], yticks=[0, 1], xticklabels=["Legit (0)", "Phish (1)"], yticklabels=["Legit (0)", "Phish (1)"],
                title=f"Baseline System (Test Set)\nAcc: {b_acc*100:.1f}%, FPs: {b_fp}, FNs: {b_fn}", ylabel="Actual", xlabel="Predicted")
    for i in range(2):
        for j in range(2):
            axes[0].text(j, i, format(cm_b[i, j], "d"), ha="center", va="center",
                         color="white" if cm_b[i, j] > cm_b.max()/2 else "black", fontsize=13, fontweight="bold")

    # Experimental CM
    cm_e = np.array([[e_tn, e_fp], [e_fn, e_tp]])
    im1 = axes[1].imshow(cm_e, interpolation="nearest", cmap=plt.cm.Greens)
    axes[1].set(xticks=[0, 1], yticks=[0, 1], xticklabels=["Legit (0)", "Phish (1)"], yticklabels=["Legit (0)", "Phish (1)"],
                title=f"Experimental System (Test Set)\nAcc: {e_acc*100:.1f}%, FPs: {e_fp}, FNs: {e_fn}", ylabel="Actual", xlabel="Predicted")
    for i in range(2):
        for j in range(2):
            axes[1].text(j, i, format(cm_e[i, j], "d"), ha="center", va="center",
                         color="white" if cm_e[i, j] > cm_e.max()/2 else "black", fontsize=13, fontweight="bold")

    plt.tight_layout()
    cm_plot_path = EXP_REPORTS_DIR / "experimental_confusion_matrix.png"
    plt.savefig(cm_plot_path, dpi=200)
    plt.close()
    print(f"Saved confusion matrix comparison plot -> {cm_plot_path}")

    print("\n" + "=" * 80)
    print("FINAL UNBIASED COMPARISON SUMMARY (HELD-OUT TEST SET: 110 SAMPLES)")
    print("=" * 80)
    print(f"{'Metric':<22} | {'Baseline System':<18} | {'Experimental System':<20} | {'Delta':<10}")
    print("-" * 80)
    print(f"{'Accuracy':<22} | {b_acc*100:>16.2f}% | {e_acc*100:>18.2f}% | {comparison_metrics['delta']['accuracy_change']:>+8.2f}%")
    print(f"{'Precision':<22} | {b_prec*100:>16.2f}% | {e_prec*100:>18.2f}% | {e_prec*100 - b_prec*100:>+8.2f}%")
    print(f"{'Phishing Recall':<22} | {b_rec*100:>16.2f}% | {e_rec*100:>18.2f}% | {e_rec*100 - b_rec*100:>+8.2f}%")
    print(f"{'F1-Score':<22} | {b_f1*100:>16.2f}% | {e_f1*100:>18.2f}% | {comparison_metrics['delta']['f1_change']:>+8.2f}%")
    print(f"{'Specificity':<22} | {b_spec*100:>16.2f}% | {e_spec*100:>18.2f}% | {e_spec*100 - b_spec*100:>+8.2f}%")
    print(f"{'False Positive Rate':<22} | {b_fpr*100:>16.2f}% | {e_fpr*100:>18.2f}% | {-comparison_metrics['delta']['fpr_reduction']:>+8.2f}%")
    print(f"{'False Negative Rate':<22} | {b_fnr*100:>16.2f}% | {e_fnr*100:>18.2f}% | {e_fnr*100 - b_fnr*100:>+8.2f}%")
    print(f"{'False Positives (count)':<22} | {b_fp:>17d} | {e_fp:>19d} | {comparison_metrics['delta']['false_positives']:>+8d}")
    print(f"{'False Negatives (count)':<22} | {b_fn:>17d} | {e_fn:>19d} | {comparison_metrics['delta']['false_negatives']:>+8d}")
    print("=" * 80)

if __name__ == "__main__":
    run_evaluation()
