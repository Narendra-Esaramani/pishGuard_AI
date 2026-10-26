"""
Feature schema definition, ordered feature names, groups, types,
safe defaults, and rule-threshold (RT) derivations for the Phishing Detection Pipeline.
"""
from typing import Dict, List, Any, Tuple
import numpy as np

# 28 Pure URL & Domain structural features (100% extractable from URL string alone)
URL_FEATURE_NAMES: List[str] = [
    'NumDots',
    'SubdomainLevel',
    'PathLevel',
    'UrlLength',
    'NumDash',
    'NumDashInHostname',
    'AtSymbol',
    'TildeSymbol',
    'NumUnderscore',
    'NumPercent',
    'NumQueryComponents',
    'NumAmpersand',
    'NumHash',
    'NumNumericChars',
    'NoHttps',
    'RandomString',
    'IpAddress',
    'DomainInSubdomains',
    'DomainInPaths',
    'HttpsInHostname',
    'HostnameLength',
    'PathLength',
    'QueryLength',
    'DoubleSlashInPath',
    'NumSensitiveWords',
    'EmbeddedBrandName',
    'SubdomainLevelRT',
    'UrlLengthRT'
]

# 20 HTML DOM & Content features (extractable only when webpage is retrieved)
HTML_FEATURE_NAMES: List[str] = [
    'PctExtHyperlinks',
    'PctExtResourceUrls',
    'ExtFavicon',
    'InsecureForms',
    'RelativeFormAction',
    'ExtFormAction',
    'AbnormalFormAction',
    'PctNullSelfRedirectHyperlinks',
    'FrequentDomainNameMismatch',
    'FakeLinkInStatusBar',
    'RightClickDisabled',
    'PopUpWindow',
    'SubmitInfoToEmail',
    'IframeOrFrame',
    'MissingTitle',
    'ImagesOnlyInForm',
    'PctExtResourceUrlsRT',
    'AbnormalExtFormActionR',
    'ExtMetaScriptLinkRT',
    'PctExtNullSelfRedirectHyperlinksRT'
]

# Complete 48-feature schema matching training dataset and model expectation
FEATURE_NAMES: List[str] = [
    'NumDots',
    'SubdomainLevel',
    'PathLevel',
    'UrlLength',
    'NumDash',
    'NumDashInHostname',
    'AtSymbol',
    'TildeSymbol',
    'NumUnderscore',
    'NumPercent',
    'NumQueryComponents',
    'NumAmpersand',
    'NumHash',
    'NumNumericChars',
    'NoHttps',
    'RandomString',
    'IpAddress',
    'DomainInSubdomains',
    'DomainInPaths',
    'HttpsInHostname',
    'HostnameLength',
    'PathLength',
    'QueryLength',
    'DoubleSlashInPath',
    'NumSensitiveWords',
    'EmbeddedBrandName',
    'PctExtHyperlinks',
    'PctExtResourceUrls',
    'ExtFavicon',
    'InsecureForms',
    'RelativeFormAction',
    'ExtFormAction',
    'AbnormalFormAction',
    'PctNullSelfRedirectHyperlinks',
    'FrequentDomainNameMismatch',
    'FakeLinkInStatusBar',
    'RightClickDisabled',
    'PopUpWindow',
    'SubmitInfoToEmail',
    'IframeOrFrame',
    'MissingTitle',
    'ImagesOnlyInForm',
    'SubdomainLevelRT',
    'UrlLengthRT',
    'PctExtResourceUrlsRT',
    'AbnormalExtFormActionR',
    'ExtMetaScriptLinkRT',
    'PctExtNullSelfRedirectHyperlinksRT'
]

# Neutral fallbacks
DEFAULT_FEATURE_VALUES: Dict[str, float] = {
    'NumDots': 2.0,
    'SubdomainLevel': 0.0,
    'PathLevel': 0.0,
    'UrlLength': 20.0,
    'NumDash': 0.0,
    'NumDashInHostname': 0.0,
    'AtSymbol': 0.0,
    'TildeSymbol': 0.0,
    'NumUnderscore': 0.0,
    'NumPercent': 0.0,
    'NumQueryComponents': 0.0,
    'NumAmpersand': 0.0,
    'NumHash': 0.0,
    'NumNumericChars': 0.0,
    'NoHttps': 0.0,
    'RandomString': 0.0,
    'IpAddress': 0.0,
    'DomainInSubdomains': 0.0,
    'DomainInPaths': 0.0,
    'HttpsInHostname': 0.0,
    'HostnameLength': 15.0,
    'PathLength': 0.0,
    'QueryLength': 0.0,
    'DoubleSlashInPath': 0.0,
    'NumSensitiveWords': 0.0,
    'EmbeddedBrandName': 0.0,
    'PctExtHyperlinks': 0.0,
    'PctExtResourceUrls': 0.0,
    'ExtFavicon': 0.0,
    'InsecureForms': 0.0,
    'RelativeFormAction': 0.0,
    'ExtFormAction': 0.0,
    'AbnormalFormAction': 0.0,
    'PctNullSelfRedirectHyperlinks': 0.0,
    'FrequentDomainNameMismatch': 0.0,
    'FakeLinkInStatusBar': 0.0,
    'RightClickDisabled': 0.0,
    'PopUpWindow': 0.0,
    'SubmitInfoToEmail': 0.0,
    'IframeOrFrame': 0.0,
    'MissingTitle': 0.0,
    'ImagesOnlyInForm': 0.0,
    'SubdomainLevelRT': 1.0,
    'UrlLengthRT': 1.0,
    'PctExtResourceUrlsRT': 1.0,
    'AbnormalExtFormActionR': 1.0,
    'ExtMetaScriptLinkRT': 1.0,
    'PctExtNullSelfRedirectHyperlinksRT': 1.0
}

# Rule Threshold Derivations (1: Legitimate, 0: Suspicious, -1: Phishing)
def compute_subdomain_level_rt(subdomain_level: int) -> int:
    if subdomain_level <= 1:
        return 1
    elif subdomain_level == 2:
        return 0
    else:
        return -1

def compute_url_length_rt(url_length: int) -> int:
    if url_length <= 54:
        return 1
    elif 54 < url_length <= 75:
        return 0
    else:
        return -1

def compute_pct_ext_resource_urls_rt(pct: float) -> int:
    if pct < 0.22:
        return 1
    elif 0.22 <= pct < 0.61:
        return 0
    else:
        return -1

def compute_abnormal_ext_form_action_r(abnormal_action: int, ext_action: int) -> int:
    if abnormal_action == 1:
        return -1
    elif ext_action == 1:
        return 0
    else:
        return 1

def compute_ext_meta_script_link_rt(pct: float) -> int:
    if pct < 0.17:
        return 1
    elif 0.17 <= pct < 0.81:
        return 0
    else:
        return -1

def compute_pct_ext_null_self_redirect_rt(pct: float) -> int:
    if pct < 0.31:
        return 1
    elif 0.31 <= pct < 0.67:
        return 0
    else:
        return -1

def validate_and_order_features(raw_features: Dict[str, Any]) -> Tuple[Dict[str, float], int, int]:
    """
    Validates features and returns:
    (ordered_features_dict, total_available_count, total_expected_count)
    """
    ordered = {}
    extracted_count = 0
    for name in FEATURE_NAMES:
        if name in raw_features and raw_features[name] is not None and not np.isnan(float(raw_features[name])):
            ordered[name] = float(raw_features[name])
            extracted_count += 1
        elif name in DEFAULT_FEATURE_VALUES:
            ordered[name] = float(DEFAULT_FEATURE_VALUES[name])
        else:
            raise ValueError(f"Missing required feature without default: {name}")
    return ordered, extracted_count, len(FEATURE_NAMES)
