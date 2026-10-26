# Phishing Detection System — Comprehensive Evaluation Report

## 1. Executive Summary
This report presents empirical evaluation results for the **Enhanced Phishing Detection System**, trained and tested on the 48-feature benchmark dataset.

- **Primary Deployed Model**: `XGBoost` (XGBClassifier)
- **Evaluated Test Partition**: 1917 samples (strictly held-out test split)
- **Overall Accuracy**: **98.80%**
- **Phishing Detection Recall (Sensitivity)**: **99.02%**
- **Legitimate Site Specificity**: **98.60%**
- **F1-Score**: **98.75%**
- **ROC-AUC**: **99.95%**
- **False Negative Rate (FNR)**: **0.98%**
- **False Positive Rate (FPR)**: **1.40%**

---

## 2. Multi-Model Benchmark Comparison
All models were trained under identical stratified 80/20 splits with feature leak prevention:

| Model Architecture | Accuracy | Precision | Phishing Recall | F1-Score | ROC-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | 98.44% | 98.05% | 98.69% | 98.37% | 99.91% |
| **XGBoost** | 98.80% | 98.48% | 99.02% | 98.75% | 99.95% |
| **Decision Tree** | 97.29% | 96.86% | 97.49% | 97.17% | 97.09% |
| **Logistic Regression** | 95.15% | 93.83% | 96.18% | 94.99% | 98.80% |
| **KNN** | 85.76% | 83.06% | 88.22% | 85.56% | 92.34% |
| **SVM (RBF)** | 85.76% | 82.14% | 89.75% | 85.77% | 94.53% |

---

## 3. Confusion Matrix Breakdown
The confusion matrix on the held-out test set (1917 samples):

```text

+-----------------------+-----------------------------+
| Actual / Predicted    | Pred: Legitimate | Pred: Phishing  |
+-----------------------+------------------+-----------------+
| Actual: Legitimate (0)| TN = 986         | FP = 14          |
| Actual: Phishing   (1)| FN = 9           | TP = 908         |
+-----------------------+------------------+-----------------+
Total Evaluated Samples: 1917

```

- **True Negatives (TN)**: 986 legitimate sites correctly classified as safe.
- **False Positives (FP)**: 14 legitimate sites falsely flagged as phishing (1.40% FPR).
- **False Negatives (FN)**: 9 phishing sites missed (0.98% FNR).
- **True Positives (TP)**: 908 phishing attacks correctly detected (99.02% Phishing Recall).

---

## 4. Generalization & Reliability Assessment
- **Dataset Source**: Strictly Held-Out Benchmark Partition (stratified 20% unseen test set)
- **Brier Score Loss**: 0.0090 (demonstrating calibrated probability estimates)
- **Matthews Correlation Coefficient (MCC)**: 0.9760 (indicating strong predictive correlation across classes)
- **Verdict**: Robust generalization verified with F1-Score of 98.75% and ROC-AUC of 99.95%
