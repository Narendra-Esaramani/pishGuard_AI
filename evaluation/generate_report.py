"""
Comprehensive evaluation report generator.
Produces markdown documentation based on actual test results.
"""
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DOCS_DIR, METADATA_PATH
from evaluation.generalization_test import run_generalization_test
from evaluation.confusion_matrix import format_confusion_matrix_text

def generate_evaluation_report() -> str:
    """Generates evaluation report markdown file from actual performance tests."""
    gen_results = run_generalization_test()
    metrics = gen_results["metrics"]
    cm = metrics["confusion_matrix"]
    
    metadata = {}
    if METADATA_PATH.exists():
        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            metadata = json.load(f)
            
    benchmarks = metadata.get("all_model_benchmarks", {})
    
    benchmark_table_rows = []
    for model_name, m in benchmarks.items():
        benchmark_table_rows.append(
            f"| **{model_name}** | {m['accuracy']*100:.2f}% | {m['precision']*100:.2f}% | {m['recall']*100:.2f}% | {m['f1_score']*100:.2f}% | {m['roc_auc']*100:.2f}% |"
        )
    benchmark_table = "\n".join(benchmark_table_rows)

    report_content = f"""# Phishing Detection System — Comprehensive Evaluation Report

## 1. Executive Summary
This report presents empirical evaluation results for the **Enhanced Phishing Detection System**, trained and tested on the 48-feature benchmark dataset.

- **Primary Deployed Model**: `{metadata.get('model_name', 'XGBoost')}` ({metadata.get('algorithm_class', 'XGBClassifier')})
- **Evaluated Test Partition**: {gen_results['sample_count']} samples (strictly held-out test split)
- **Overall Accuracy**: **{metrics['accuracy']*100:.2f}%**
- **Phishing Detection Recall (Sensitivity)**: **{metrics['recall']*100:.2f}%**
- **Legitimate Site Specificity**: **{metrics['specificity']*100:.2f}%**
- **F1-Score**: **{metrics['f1_score']*100:.2f}%**
- **ROC-AUC**: **{metrics['roc_auc']*100:.2f}%**
- **False Negative Rate (FNR)**: **{metrics['fnr']*100:.2f}%**
- **False Positive Rate (FPR)**: **{metrics['fpr']*100:.2f}%**

---

## 2. Multi-Model Benchmark Comparison
All models were trained under identical stratified 80/20 splits with feature leak prevention:

| Model Architecture | Accuracy | Precision | Phishing Recall | F1-Score | ROC-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- |
{benchmark_table}

---

## 3. Confusion Matrix Breakdown
The confusion matrix on the held-out test set ({gen_results['sample_count']} samples):

```text
{format_confusion_matrix_text(cm)}
```

- **True Negatives (TN)**: {cm['tn']} legitimate sites correctly classified as safe.
- **False Positives (FP)**: {cm['fp']} legitimate sites falsely flagged as phishing ({metrics['fpr']*100:.2f}% FPR).
- **False Negatives (FN)**: {cm['fn']} phishing sites missed ({metrics['fnr']*100:.2f}% FNR).
- **True Positives (TP)**: {cm['tp']} phishing attacks correctly detected ({metrics['recall']*100:.2f}% Phishing Recall).

---

## 4. Generalization & Reliability Assessment
- **Dataset Source**: {gen_results['dataset_source']}
- **Brier Score Loss**: {metrics['brier_score']:.4f} (demonstrating calibrated probability estimates)
- **Matthews Correlation Coefficient (MCC)**: {metrics['mcc']:.4f} (indicating strong predictive correlation across classes)
- **Verdict**: {gen_results['generalization_verdict']}
"""
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DOCS_DIR / "evaluation.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    print(f"Evaluation report generated -> {report_path}")
    return report_content

if __name__ == "__main__":
    generate_evaluation_report()
