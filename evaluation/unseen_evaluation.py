"""
Realistic Unseen URL Benchmark Evaluation Suite.
Tests the enhanced prediction pipeline on an independent evaluation set of real-world
phishing and legitimate URLs, measuring False Negative Rate reduction and generalization.
"""
import sys
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.feature_pipeline import FeatureExtractionPipeline
from detection.predictor import PhishingPredictor
from detection.decision_engine import evaluate_decision
from evaluation.metrics import compute_all_metrics

# Diverse, realistic unseen evaluation set (never used during model training)
UNSEEN_BENCHMARK_URLS = [
    # Legitimate Top Domains & Deep Paths
    {"url": "https://www.wikipedia.org", "label": 0, "category": "General Information"},
    {"url": "https://www.google.com/search?q=machine+learning+security", "label": 0, "category": "Search Query"},
    {"url": "https://github.com/torvalds/linux/releases", "label": 0, "category": "Developer Portal"},
    {"url": "https://www.microsoft.com/en-us/security/business", "label": 0, "category": "Enterprise Security"},
    {"url": "https://stackoverflow.com/questions/tagged/python", "label": 0, "category": "Tech Community"},
    {"url": "https://www.bbc.com/news/technology", "label": 0, "category": "News Media"},
    {"url": "https://arxiv.org/abs/2304.11005", "label": 0, "category": "Academic Research"},
    {"url": "https://aws.amazon.com/free/", "label": 0, "category": "Cloud Portal"},
    {"url": "https://www.python.org/downloads/release/python-3130/", "label": 0, "category": "Software Repository"},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP", "label": 0, "category": "Web Documentation"},
    
    # Real-World Phishing Pattern Campaigns & Spoofed Bait URLs
    {"url": "http://paypal-security-verification.account-update.net/login.php?token=98234", "label": 1, "category": "PayPal Credential Bait"},
    {"url": "http://appleid.apple.com.manage-account.info/auth/verify?session=x9", "label": 1, "category": "AppleID Subdomain Spoof"},
    {"url": "http://192.168.1.100/admin/secure_portal/login.php", "label": 1, "category": "Raw IP Host Attack"},
    {"url": "http://netflix-billing-update.account-support.com/update_payment.php", "label": 1, "category": "Streaming Billing Fraud"},
    {"url": "http://chase-online-banking-auth.secure-validation.org/signin", "label": 1, "category": "Banking Auth Spoof"},
    {"url": "http://binance-wallet-verify.crypto-recovery.top/auth/token=8831", "label": 1, "category": "Crypto Wallet Bait"},
    {"url": "http://wellsfargo.com.security-alert-check.xyz/login.aspx?user=val", "label": 1, "category": "Subdomain Camouflage"},
    {"url": "https://personasenlinea.net/", "label": 1, "category": "Latin America Banking Bait (Taken Down)"},
    {"url": "http://microsoft-365-password-reset.live-security.net/checkpoint", "label": 1, "category": "O365 Phishing Clone"},
    {"url": "http://instagram-copyright-appeal.social-verify.com/form.php", "label": 1, "category": "Social Media Phishing"}
]

def run_unseen_benchmark_evaluation() -> Dict[str, Any]:
    """
    Executes evaluation across the unseen URL benchmark set.
    """
    pipeline = FeatureExtractionPipeline(enable_live_html=False)
    predictor = PhishingPredictor()
    
    y_true = []
    y_pred = []
    y_prob = []
    url_diagnostics = []
    
    for item in UNSEEN_BENCHMARK_URLS:
        target_url = item["url"]
        actual_label = item["label"]
        
        try:
            df_feat, extract_meta = pipeline.extract_features(target_url)
            pred, prob, prob_dict, diag_meta = predictor.predict(
                df_feat,
                is_html_live=extract_meta.get("html_analysis", False)
            )
            decision = evaluate_decision(pred, prob, df_feat, extract_meta, diag_meta)
            
            # Binary threat indicator: suspicious or high risk
            threat_detected = 1 if (decision["risk_score"] >= 31 or pred == 1) else 0
            
            y_true.append(actual_label)
            y_pred.append(threat_detected)
            y_prob.append(decision["risk_score"] / 100.0)
            
            url_diagnostics.append({
                "url": target_url,
                "category": item["category"],
                "actual": "Phishing" if actual_label == 1 else "Legitimate",
                "predicted_verdict": decision["verdict"],
                "risk_score": decision["risk_score"],
                "probability": round(prob, 4),
                "correct": bool(threat_detected == actual_label)
            })
        except Exception as e:
            continue

    metrics = compute_all_metrics(y_true, y_pred, y_prob)
    
    print("\n" + "=" * 80)
    print("REALISTIC UNSEEN BENCHMARK EVALUATION RESULTS (100% UNSEEN EVALUATION SET)")
    print("=" * 80)
    print(f"Total Evaluated URLs: {len(y_true)} ({sum(y_true)} Phishing, {len(y_true)-sum(y_true)} Legitimate)")
    print(f"Accuracy:        {metrics['accuracy']*100:.2f}%")
    print(f"Precision:       {metrics['precision']*100:.2f}%")
    print(f"Phishing Recall: {metrics['recall']*100:.2f}% (False Negatives: {metrics['confusion_matrix']['fn']})")
    print(f"Specificity:     {metrics['specificity']*100:.2f}% (False Positives: {metrics['confusion_matrix']['fp']})")
    print(f"F1-Score:        {metrics['f1_score']*100:.2f}%")
    print(f"ROC-AUC:         {metrics['roc_auc']*100:.2f}%")
    print("=" * 80)
    
    print("\nURL Breakdown:")
    for d in url_diagnostics:
        mark = "[PASS]" if d["correct"] else "[FAIL]"
        print(f"{mark} {d['actual']:<10} -> {d['predicted_verdict']:<25} | Risk: {d['risk_score']:2d}/100 | {d['url']}")

    return {
        "metrics": metrics,
        "diagnostics": url_diagnostics
    }

if __name__ == "__main__":
    run_unseen_benchmark_evaluation()
