import os
import ipaddress
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
RAW_DATA_PATH = DATA_DIR / 'raw' / 'Phishing_Legitimate_full.csv'
PROCESSED_DATA_PATH = DATA_DIR / 'processed' / 'clean_dataset.csv'
FEEDBACK_CSV_PATH = DATA_DIR / 'feedback' / 'feedback.csv'
MODELS_DIR = BASE_DIR / 'models'
MODEL_PATH = MODELS_DIR / 'phishing_model.pkl'
FEATURE_NAMES_PATH = MODELS_DIR / 'feature_names.pkl'
SCALER_PATH = MODELS_DIR / 'scaler.pkl'
METADATA_PATH = MODELS_DIR / 'model_metadata.json'
METRICS_PATH = MODELS_DIR / 'model_metrics.json'
LOGS_DIR = BASE_DIR / 'logs'
DOCS_DIR = BASE_DIR / 'docs'

# Application Settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-secure-secret-key-2026')
DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('1', 'true', 'yes')
PORT = int(os.environ.get('PORT', 5000))
HOST = os.environ.get('HOST', '127.0.0.1')

# Risk Score Thresholds
RISK_THRESHOLD_SAFE_MAX = 30
RISK_THRESHOLD_SUSPICIOUS_MAX = 69
RISK_THRESHOLD_HIGH_MIN = 70

# Feature Extraction & Network Security Settings
REQUEST_TIMEOUT_SECONDS = 3.5
REQUEST_TIMEOUT = 3.5
MAX_HTML_BODY_BYTES = 1024 * 1024  # 1 MB maximum download size
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard-PassiveSecurityResearch/1.0'

BLOCKED_IP_PREFIXES = (
    '127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
    '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
    '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.',
    '169.254.', '0.', '::1', 'fc00:', 'fe80:'
)
BLOCKED_HOSTNAMES = {'localhost', 'loopback', '127.0.0.1', '::1'}

SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10')
]

# Sensitive Keywords for Phishing Pattern Heuristics
SENSITIVE_WORDS = [
    'secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin',
    'banking', 'confirm', 'update', 'verify', 'password', 'authenticate',
    'wallet', 'service', 'support', 'billing', 'recovery', 'alert',
    'checkpoint', 'security', 'validation', 'access', 'authorize',
    'appleid', 'office365', 'microsoft365', 'token', 'credential'
]

# High-profile Brands for Embedded Brand Spoofing Check
COMMON_BRAND_NAMES = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'chase', 'bankofamerica', 'wellsfargo',
    'citi', 'yahoo', 'outlook', 'dropbox', 'ebay', 'binance', 'coinbase',
    'aquent', 'docusign', 'metamask', 'zoom', 'fedex', 'dhl', 'usps'
]

# Experimental Evidence-Synthesis Settings (Switchable; default is False)
ENABLE_EXPERIMENTAL_SYNTHESIS = os.environ.get('ENABLE_EXPERIMENTAL_SYNTHESIS', 'False').lower() in ('1', 'true', 'yes')
EXPERIMENTAL_DECISION_THRESHOLD = float(os.environ.get('EXPERIMENTAL_DECISION_THRESHOLD', 0.65))


