# PhishGuard AI — Enhanced Explainable Phishing Detection System


 ## 🚀 Live Demo

**Try PhishGuard AI online:** [Open the Live Application](https://pishguard-ai-6qw6.onrender.com)

Analyze URLs to identify potential phishing threats using machine learning.

> Note: The application is hosted on Render's free tier, so the first request after inactivity may take some time to load.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask%203.0-green.svg)](https://flask.palletsprojects.com/)
[![Model: XGBoost](https://img.shields.io/badge/Model-XGBoost%20Calibrated-orange.svg)](https://xgboost.readthedocs.io/)
[![Explainability: SHAP](https://img.shields.io/badge/Explainability-SHAP-purple.svg)](https://shap.readthedocs.io/)
[![Tests: Pytest (35 passed)](https://img.shields.io/badge/Tests-35%20Passed-brightgreen.svg)](https://docs.pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-ready, research-grade phishing website detection and threat analysis system. PhishGuard AI advances machine-learning cybersecurity research beyond static tabular classifiers by providing an **end-to-end automated detection pipeline, an adaptive multi-channel Evidence-Synthesis Layer, and model-agnostic explainability (SHAP & LIME)**.

---

## 📌 Research Context & Base Paper Evolution

This implementation is inspired by and substantially extends the IEEE conference publication:

> **"Enhancing Phishing Detection using Machine Learning Algorithms"**  
> *IEEE International Conference on Computing, Communication, and Intelligent Systems (April 23–25, 2025; Published May 23, 2025; IEEE Xplore Document ID: 11005375)*

### Limitations of the Base Paper Approach:
1. **Static Tabular Dependency:** Required manual pre-extraction of 48 numeric feature values from static CSV records; lacked an automated live URL feature extraction engine.
2. **Forced Binary Decisions:** Forced ambiguous, offline, or newly registered domains into rigid binary buckets (`0 = Legitimate`, `1 = Phishing`), resulting in false certainty.
3. **Missing-HTML Degradation:** When offline or unreachable, models trained on all 48 features suffer severe feature distortion because missing DOM features simulate phishing anomalies.
4. **Deep Path False Positives:** Legitimate documentation, scientific articles, and technical blogs with deep directory hierarchies (`PathLevel >= 2`, `/docs/Web/HTTP`) share lexical characteristics with compromised host phishing traps, leading to false alarms.

### How PhishGuard AI Resolves These Limitations:
- **Zero-Input Automated Extraction:** Analyzes raw URL strings (`https://example.com/login`) directly, automatically deriving all 48 lexical, domain telemetry, and DOM content features in real time.
- **Adaptive Dual-Pipeline:** Employs an offline-resilient 28-feature lexical classifier when websites are unreachable, and a full 48-feature hybrid model when live HTML DOM is retrieved.
- **Multi-Channel Evidence Synthesis:** Fuses ML probability, hostname integrity, public-suffix structural ratios, and DNS/SSL telemetry to emit tri-state verdicts:
  - 🟢 **`LIKELY LEGITIMATE`** (Risk 0–30)
  - 🟡 **`SUSPICIOUS (NEEDS REVIEW)`** (Risk 31–69)
  - 🔴 **`LIKELY PHISHING`** (Risk 70–100)
- **Local Feature Explainability:** Computes SHAP Shapley values and natural language narratives explaining *precisely why* a URL was flagged.
- **Enterprise Safety Controls:** Strict Server-Side Request Forgery (SSRF) boundary guards blocking private IPv4/IPv6 subnets, passive scraping caps (1 MB body limit), and strict 3.5s timeouts.

---

## 🏗️ System Architecture

```text
                                     Target URL Input
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
          URL Lexical Extractor                        Domain Telemetry Engine
         (28 Lexical & RT Features)                   (DNS, TLD, SSL, SSRF Guard)
                     │                                             │
                     └──────────────────────┬──────────────────────┘
                                            │
                             Is Website Live & Reachable?
                                    /               \
                             [YES] /                 \ [NO]
                                  ▼                   ▼
                         Passive DOM Scraper      Offline Resilient Fallback
                         (20 Content Features)    (Uncertainty Protocol)
                                  │                   │
                                  └─────────┬─────────┘
                                            │
                                            ▼
                                  Adaptive Model Layer
                           (Calibrated XGBoost Ensembles)
                                            │
                                            ▼
                            Evidence-Synthesis Layer
             ┌─────────────────────────────────────────────────────────────┐
             │ - Hostname vs. Path Structural Symmetry                     │
             │ - Deceptive Subdomain Brand Camouflage Check                │
             │ - DNS & SSL Telemetry Concordance                           │
             │ - Contradiction & Uncertainty Resolution                    │
             └──────────────────────────────┬──────────────────────────────┘
                                            │
                                            ▼
                     ┌─────────────────────────────────────────────┐
                     │ Tri-State Security Verdict (Safe/Review/Risk)│
                     │ Calibrated Security Risk Score (0 - 100)    │
                     │ SHAP Feature Attribution & Explanations     │
                     └─────────────────────────────────────────────┘
```

---

## 🚀 Key Features

- **Automated 48-Feature Extraction:** Evaluates length metrics, symbol counts, token entropy, domain depth, protocol security, sensitive keywords, and iframe/form actions.
- **Calibrated Prediction Probabilities:** Utilizes `CalibratedClassifierCV` (sigmoid calibration) to ensure model confidence values reflect observed threat frequencies.
- **Explainable AI (XAI):** Built-in SHAP TreeExplainer integration providing top positive and negative contributing factors for every scanned URL.
- **Analyst Feedback & Guardrailed Retraining:** Feedback registry allowing security analysts to correct verdicts with automated regression guardrails before model promotion.
- **Adversarial Robustness Testing:** Automated perturbation test suite testing decision stability across 5 syntactic URL mutations.
- **RESTful API & Responsive UI:** Modern cybersecurity analyst interface featuring an interactive SVG threat gauge, diagnostics dashboard, and JSON endpoints.

---

## 📦 Repository Structure

```text
Enhanced_phishing_detection/
├── run.py                              # Application entrypoint (WSGI app instance)
├── config.py                           # Application configuration, thresholds & guards
├── requirements.txt                    # Project dependencies
├── .env.example                        # Example environment configuration
├── .gitignore                          # Git exclusion rules
│
├── app/                                # Flask Web Application
│   ├── app.py                          # Application factory & route handlers
│   ├── templates/                      # Jinja2 HTML templates (Dashboard, Diagnostics)
│   └── static/                         # CSS styling & SVG threat meter gauge
│
├── api/                                # REST API
│   ├── routes.py                       # /api/analyze, /api/model-info, /api/feedback
│   └── schemas.py                      # Request validation & response schemas
│
├── detection/                          # Detection & Decision Engines
│   ├── predictor.py                    # Singleton inference with dynamic class mapping
│   ├── evidence_synthesis.py           # Multi-channel evidence synthesis & contradiction handler
│   ├── decision_engine.py              # Security decision evaluator (Baseline & Experimental)
│   ├── risk_score.py                   # 0-100 risk score calibration
│   └── result_formatter.py             # Security report serializer
│
├── feature_extraction/                 # Feature Extraction Pipeline
│   ├── url_features.py                 # Lexical feature extraction (28 features)
│   ├── domain_features.py              # Domain metadata, tldextract & SSRF guards
│   ├── html_features.py                # Passive DOM content extraction (20 features)
│   ├── feature_schema.py               # Authoritative 48-feature schema & RT rules
│   └── feature_pipeline.py             # Orchestrator with validation checks
│
├── explainability/                     # Explainable AI Services
│   ├── shap_explainer.py               # SHAP TreeExplainer service
│   ├── lime_explainer.py               # LIME fallback explainer
│   └── explanation_generator.py        # Natural language translation engine
│
├── models/                             # Trained Artifacts & Metadata (< 3 MB total)
│   ├── phishing_model.pkl              # Calibrated Full 48-feature model
│   ├── url_model.pkl                   # Calibrated 28-feature pure URL model
│   ├── raw_phishing_model.pkl          # Booster for SHAP TreeExplainer
│   ├── feature_names.pkl               # 48 feature schema order
│   └── model_metadata.json             # Calibration metrics & threshold curves
│
├── data/                               # Benchmark Datasets
│   ├── raw/Phishing_Legitimate_full.csv # Base paper raw dataset (10,000 samples)
│   └── processed/clean_dataset.csv     # Cleaned, deduplicated dataset (9,581 samples)
│
├── reports/                            # Baseline & Root-Cause Reports
│   ├── false_positive_root_cause.md    # Deep 49-FP investigation report
│   ├── false_positive_feature_analysis.csv # SHAP attribution breakdown
│   ├── calibration_curve.png           # Reliability calibration plot
│   └── experimental/                   # Experimental Evaluation Reports
│       ├── threshold_validation_sweep.csv
│       ├── baseline_vs_experimental_test_metrics.json
│       ├── experimental_confusion_matrix.png
│       └── experimental_predictions.csv
│
└── tests/                              # Automated Test Suite (35 tests)
    ├── test_api.py                     # API endpoint verification
    ├── test_domain_features.py         # Domain metadata & SSRF validation
    ├── test_experimental_synthesis.py  # Unit tests for experimental synthesis
    ├── test_regression.py              # End-to-end regression tests
    ├── test_url_features.py            # Lexical feature extractors
    └── evaluate_experimental.py        # Validation split & held-out evaluation runner
```

---

## ⚙️ Installation & Setup (Windows & Cross-Platform)

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### 2. Clone the Repository
```powershell
git clone https://github.com/<YOUR_USERNAME>/PhishGuard-AI.git
cd PhishGuard-AI
```

### 3. Create and Activate Virtual Environment
```powershell
# Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Start the Application
```powershell
python run.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🔐 Environment Variables & Security Configuration

Copy `.env.example` to `.env` to customize settings:

```ini
# Security Secret Key (Set a strong random string in production)
SECRET_KEY=your-secure-random-secret-key-here

# Server Settings
HOST=127.0.0.1
PORT=5000
FLASK_DEBUG=False

# Evidence-Synthesis Configuration (Default: False for baseline preservation)
ENABLE_EXPERIMENTAL_SYNTHESIS=False
EXPERIMENTAL_DECISION_THRESHOLD=0.65
```

> **Security Guardrails:**
> - `FLASK_DEBUG` defaults to `False` in production to prevent interactive traceback exposure.
> - `SECRET_KEY` should be set via environment variable in deployment environments.
> - The application operates strictly in passive mode and will never execute downloaded scripts or submit credentials.

---

## 📊 Empirical Evaluation Results

### A. Training & Benchmark Dataset
- **Total Samples:** 9,581 samples from the IEEE base research benchmark.
- **Labels:** Strictly mapped (`0 = Legitimate`, `1 = Phishing`).
- **Distribution:** Balanced (52.1% Legitimate, 47.9% Phishing).

### B. Held-Out Evaluation Benchmark (110 Samples)
To evaluate the system objectively on unseen attacks and complex URLs, an independent benchmark of **210 ground-truth URLs** was constructed:
- 105 verified legitimate domains (Tranco Top-1M, academic archives, government portals, documentation hubs).
- 105 verified phishing campaigns (PhishTank, OpenPhish, URLhaus feeds).

The dataset was partitioned into a **Validation Set** (100 samples) to tune thresholds, and an untouched **Held-Out Test Set** (110 samples: 55 Legitimate, 55 Phishing) for final unbiased evaluation:

| Evaluation Metric | Baseline Pipeline (Test Set) | Experimental Synthesis (Test Set) | Observed Delta |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 68.18% | **95.45%** | **+27.27%** |
| **Precision** | 61.63% | **96.30%** | **+34.67%** |
| **Phishing Recall** | 96.36% | **94.55%** | -1.81% |
| **F1-Score** | 75.18% | **95.41%** | **+20.23%** |
| **Specificity** | 40.00% | **96.36%** | **+56.36%** |
| **False Positive Rate (FPR)** | 60.00% | **3.64%** | **-56.36%** |
| **False Negative Rate (FNR)** | 3.64% | **5.45%** | +1.81% |
| **False Positives (count)** | 33 / 55 | **2 / 55** | **-31 False Alarms** |
| **False Negatives (count)** | 2 / 55 | **3 / 55** | +1 (Captured in Review) |

> ⚠️ **Evaluation Disclaimer:**  
> These metrics reflect performance on our 110-sample held-out benchmark and should not be construed as a guarantee of 95%+ accuracy across all arbitrary real-world traffic. In particular, real-world web traffic contains evolving adversarial kits, fast-flux DNS, and unindexed top-level domains.

---

## 🧪 Running Automated Tests

Run the complete test suite (35 automated tests):
```powershell
pytest tests/ -v
```

Run the validation split and held-out test evaluation runner:
```powershell
python tests/evaluate_experimental.py
```

---

## 🌐 REST API Reference

### 1. Analyze URL
- **Endpoint:** `POST /api/analyze`
- **Request Body:**
  ```json
  {
    "url": "https://docs.python.org/3/library/socket.html"
  }
  ```
- **Response:**
  ```json
  {
    "status": "success",
    "data": {
      "verdict": "LIKELY LEGITIMATE",
      "risk_score": 12,
      "risk_level": "SAFE",
      "phishing_probability": 0.0821,
      "confidence": "HIGH",
      "critical_flags": [],
      "explanation": {
        "summary": "Authentic registered domain with hierarchical resource path.",
        "top_contributing_factors": [
          {"feature": "NoHttps", "influence": "Decreases Phishing Risk"},
          {"feature": "SubdomainLevel", "influence": "Decreases Phishing Risk"}
        ]
      }
    }
  }
  ```

### 2. Model Metadata & Status
- **Endpoint:** `GET /api/model-info`
- **Response:** Returns live model configuration, feature count, threshold evaluation curves, and feedback statistics.

### 3. Submit Analyst Feedback
- **Endpoint:** `POST /api/feedback`
- **Request Body:**
  ```json
  {
    "url": "https://example.com/login",
    "analyst_verdict": 1,
    "notes": "Verified credential harvester targeting corporate VPN."
  }
  ```

---

## ☁️ Deployment Guidelines (Production WSGI)

For deployment on Linux-based cloud platforms (e.g. Render, Railway, Fly.io, AWS EC2):

### 1. Startup Command
```bash
gunicorn run:app --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 120
```

### 2. Required Environment Variables
- `SECRET_KEY`: High-entropy random string.
- `FLASK_DEBUG`: Set to `False`.
- `ENABLE_EXPERIMENTAL_SYNTHESIS`: Set to `True` to enable the enhanced Evidence-Synthesis Layer.
- `PORT`: Injected automatically by the host platform (defaults to 5000).

### 3. Memory & Hardware Requirements
- **RAM:** Minimum 512 MB (1 GB recommended) to accommodate in-memory XGBoost boosters and SHAP TreeExplainer trees.
- **Outbound Network Access:** Standard HTTPS (port 443) and DNS (port 53) outbound egress for live domain checks.

---

## 🛡️ Responsible Disclosure & Limitations

1. **Defensive Research Scope:** PhishGuard AI is intended solely for defensive cybersecurity research, academic education, and email/web gateway telemetry triage.
2. **Passive Crawling Limits:** The passive DOM scraper does not execute dynamic JavaScript payloads or bypass Captchas/Cloudflare challenges.
3. **Offline Scan Uncertainty:** When live HTML is unreachable, the system relies on lexical and domain telemetry. Inconclusive cases are intentionally routed to `SUSPICIOUS (NEEDS REVIEW)` rather than asserting false certainty.

---

## 📜 License & Citation

Distributed under the MIT License. See `LICENSE` for details.

If you utilize this repository in your academic work, please cite:
```bibtex
@article{phishguard2026,
  title={PhishGuard AI: Explainable Machine-Learning Phishing Detection with Multi-Channel Evidence Synthesis},
  year={2026},
  note={Based on IEEE Xplore Document ID: 11005375}
}
```
