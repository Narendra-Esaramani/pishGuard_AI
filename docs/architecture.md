# System Architecture Specification

## 1. Overview
PhishGuard AI is an enhanced, explainable phishing detection architecture designed to bridge the gap between static feature-table machine learning benchmarks and practical, real-time cybersecurity defense.

```text
                                  +-----------------------+
                                  |   User Input (URL)    |
                                  +-----------+-----------+
                                              |
                                              v
                              +---------------+---------------+
                              |    URL Validation & SSRF      |
                              |       Security Filter         |
                              +---------------+---------------+
                                              |
                     +------------------------+------------------------+
                     |                        |                        |
                     v                        v                        v
          +----------+---------+   +----------+---------+   +----------+---------+
          | 26 Lexical &       |   | 6 Domain DNS &     |   | 16 Passive HTML/DOM|
          | Structural URL     |   | Network Safety     |   | Content Features   |
          | Features           |   | Features           |   | (Safe Timeout/Cap) |
          +----------+---------+   +----------+---------+   +----------+---------+
                     |                        |                        |
                     +------------------------+------------------------+
                                              |
                                              v
                              +---------------+---------------+
                              |  Feature Schema Alignment &   |
                              |  6 Rule-Threshold Derivations |
                              |      (Exact 48 Features)      |
                              +---------------+---------------+
                                              |
                                              v
                              +---------------+---------------+
                              | Trained Gradient-Boosted Tree |
                              |  Classifier (XGBoost / RF)    |
                              +---------------+---------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
          +----------+---------+                            +----------+---------+
          | Risk Scoring &     |                            | Local Explainability|
          | Decision Engine    |                            | (SHAP TreeExplainer|
          | (0-100 Gauge)      |                            | & LIME Fallback)   |
          +----------+---------+                            +----------+---------+
                     |                                                 |
                     +------------------------+------------------------+
                                              |
                                              v
                              +---------------+---------------+
                              | Human-Readable Explanation    |
                              | Generation & Factor Mapping   |
                              +---------------+---------------+
                                              |
                                              v
                              +---------------+---------------+
                              | Dynamic Security Report       |
                              | Dashboard & REST API          |
                              +---------------+---------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
          +----------+---------+                            +----------+---------+
          | Controlled URL     |                            | Verified User      |
          | Robustness Suite   |                            | Feedback Loop &    |
          | (5 Perturbations)  |                            | Retraining Engine  |
          +--------------------+                            +--------------------+
```

## 2. Architectural Layers

### Layer 1: Ingestion & SSRF Prevention
- Strictly normalizes incoming URLs.
- Validates RFC 3986 compliance.
- Blocks SSRF vectors targeting loopback addresses (`127.0.0.1`, `localhost`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local ranges (`169.254.0.0/16`).

### Layer 2: Automated Hybrid Feature Extraction Pipeline
- **URL Lexical Engine**: Extracts character counts, entropy heuristics, sensitive keyword frequencies, and brand spoofing patterns without network access.
- **Domain Engine**: Resolves DNS records, inspects TLDs, and evaluates certificate handshakes with strict 1.5s timeouts.
- **HTML DOM Engine**: Fetches web content passively (capped at 1MB and 3.5s timeout) and parses anchor targets, resource ratios, form actions, hidden frames, and script manipulations using BeautifulSoup.
- **Fallback Engine**: If a website is offline, unreachable, or in private address space, HTML features gracefully default to calibrated neutral baselines, and the system explicitly flags offline mode in the diagnostics.

### Layer 3: ML Inference & Decision Matrix
- Executes single-pass inference through cached tree ensembles.
- Validates that the input tensor strictly adheres to the 48-feature schema.
- Calculates 0-100 calibrated risk scores and maps predictions into categorical risk tiers: `SAFE`, `SUSPICIOUS`, `HIGH RISK`.

### Layer 4: Explainable AI Translation
- Calculates Shapley values via `shap.TreeExplainer`.
- Identifies the top positive (risk-increasing) and negative (risk-reducing) contributors.
- Maps technical attributions to intuitive natural language security insights.

### Layer 5: Robustness & Continuous Feedback
- Perturbs input URLs using 5 controlled syntactic mutations to measure decision invariance.
- Captures analyst feedback with validation guardrails for regression-tested model retraining.
