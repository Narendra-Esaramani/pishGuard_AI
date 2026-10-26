"""
Hybrid Feature Extraction Pipeline.
Combines URL lexical, Domain validation, and HTML/DOM analyzers into a validated
48-feature vector matching the model's exact schema, with feature completeness tracking.
"""
from typing import Dict, Any, Tuple, Optional
import pandas as pd
import numpy as np

from .feature_schema import (
    FEATURE_NAMES,
    URL_FEATURE_NAMES,
    HTML_FEATURE_NAMES,
    validate_and_order_features
)
from .url_features import extract_url_features
from .domain_features import extract_domain_features
from .html_features import extract_html_features

class FeatureExtractionPipeline:
    """
    Orchestrates live extraction of 48 features from a URL and optional HTML content.
    Guarantees strict schema validation, order preservation, and feature completeness auditing.
    """
    
    def __init__(self, enable_live_html: bool = True):
        self.enable_live_html = enable_live_html
        self.feature_names = FEATURE_NAMES
        self.url_feature_names = URL_FEATURE_NAMES
        self.html_feature_names = HTML_FEATURE_NAMES
        
    def extract_features(
        self,
        url: str,
        html_content: Optional[str] = None
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Executes end-to-end extraction from a URL string.
        
        Returns:
            df_features: 1-row pandas DataFrame with exactly 48 columns in expected order.
            metadata: Diagnostic information including domain metadata, extraction status, and completeness.
        """
        raw_combined: Dict[str, Any] = {}
        status_info = {
            "url_analysis": False,
            "domain_analysis": False,
            "html_analysis": False,
            "html_message": "",
            "domain_metadata": {},
            "features_extracted_count": 0,
            "total_features_count": len(self.feature_names),
            "feature_completeness_pct": 0.0,
            "mode": "url_only"
        }
        
        # 1. Extract URL lexical features (Mandatory - 28 features)
        url_feats = extract_url_features(url)
        raw_combined.update(url_feats)
        status_info["url_analysis"] = True
        
        # 2. Extract Domain features (Safe validation)
        try:
            domain_info = extract_domain_features(url)
            status_info["domain_metadata"] = domain_info
            status_info["domain_analysis"] = True
        except Exception as e:
            status_info["domain_metadata"] = {"error": str(e)}
            status_info["domain_analysis"] = False

        # 3. Extract HTML features (Passive / Optional - 20 features)
        if self.enable_live_html or html_content is not None:
            try:
                html_feats, html_success, html_msg = extract_html_features(url, html_content=html_content)
                if html_success and html_feats:
                    raw_combined.update(html_feats)
                    status_info["html_analysis"] = True
                    status_info["html_message"] = html_msg
                    status_info["mode"] = "full_hybrid"
                else:
                    status_info["html_analysis"] = False
                    status_info["html_message"] = html_msg or "HTML analysis unavailable (offline/unreachable)."
                    status_info["mode"] = "url_only"
            except Exception as e:
                status_info["html_analysis"] = False
                status_info["html_message"] = f"HTML analysis skipped: {str(e)}"
                status_info["mode"] = "url_only"
        else:
            status_info["html_analysis"] = False
            status_info["html_message"] = "HTML live inspection disabled by configuration."
            status_info["mode"] = "url_only"

        # 4. Validate & align to exact 48-feature schema
        ordered_features, extracted_count, total_expected = validate_and_order_features(raw_combined)
        status_info["features_extracted_count"] = extracted_count
        status_info["feature_completeness_pct"] = round(extracted_count / total_expected * 100.0, 1)
        
        # 5. Convert to single-row DataFrame
        df_row = pd.DataFrame([ordered_features], columns=self.feature_names)
        
        # Strict validation checks
        if df_row.shape[1] != len(self.feature_names):
            raise ValueError(f"Feature count mismatch: Expected {len(self.feature_names)}, got {df_row.shape[1]}")
        if list(df_row.columns) != self.feature_names:
            raise ValueError("Feature ordering mismatch detected in pipeline output.")
        if df_row.isnull().any().any():
            raise ValueError("NaN values detected in constructed feature vector.")
            
        return df_row, status_info
