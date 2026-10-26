# Base Paper Comparison & Enhancement Analysis

## 1. Reference Publication
- **Title**: *Enhancing Phishing Detection using Machine Learning Algorithms*
- **Conference**: IEEE International Conference on Computing, Communication, and Intelligent Systems
- **Conference Dates**: April 23–25, 2025
- **Publication Date**: May 23, 2025
- **IEEE Xplore Document ID**: 11005375

---

## 2. Core Contributions of the Base Paper
The IEEE base paper investigated feature-based machine learning classification for phishing website detection. Its core accomplishments include:
1. Evaluating classical machine learning algorithms (Random Forest, Decision Tree, Logistic Regression, SVM) on phishing datasets.
2. Demonstrating the importance of multi-factor structural and content attributes in identifying fraudulent landing pages.
3. Achieving high statistical classification accuracy on pre-extracted feature tables.

---

## 3. Practical Limitations of the Base Paper Paradigm
While foundational, traditional base-paper implementations exhibit several critical operational limitations:

1. **Manual Feature Requirement**: The base paper assumes a pre-extracted feature vector. In real-world deployment, a user cannot manually input 48 numeric feature values.
2. **Offline Static Scope**: Evaluation is restricted to static CSV datasets; no live URL extraction, DNS resolution, or passive HTML scraping pipelines are provided.
3. **Black-Box Opacity**: Traditional classifiers return binary predictions (0 or 1) without explaining *why* a website was flagged.
4. **Lack of Adversarial Stability Testing**: Classifiers are evaluated solely on static test partitions without measuring sensitivity to minor URL perturbations.
5. **Absence of Continuous Learning & Retraining Safeguards**: No feedback mechanism exists to capture emerging phishing campaigns or retrain models safely.

---

## 4. Systematic Enhancement Matrix

| Feature / Capability | Base Paper Approach | PhishGuard AI Enhanced System |
| :--- | :--- | :--- |
| **Input Workflow** | Requires manual entry of 48 feature values. | **Single URL Entry**: 100% automated live feature extraction. |
| **Feature Extraction** | Pre-computed static CSV table. | **Real-Time Hybrid Pipeline**: Lexical URL + Domain DNS + Passive DOM. |
| **Explainable AI (XAI)** | None (Black-box classification). | **SHAP TreeExplainer + Natural Language Translation**. |
| **Risk Representation** | Binary 0/1 indicator. | **0–100 Calibrated Risk Score** with categorical risk tiers. |
| **Adversarial Robustness** | Unaddressed. | **Controlled Perturbation Suite** with 5 mutation operators. |
| **Security Safeguards** | None. | **SSRF Prevention**, private IP blocking, 1MB size caps, 3.5s timeouts. |
| **Feedback & Retraining** | Static static weights. | **Verified Feedback Registry + Guardrailed Retraining Pipeline**. |
| **User Interface** | CLI / Offline Jupyter Notebook. | **Modern Responsive Cybersecurity Web Dashboard + REST API**. |
