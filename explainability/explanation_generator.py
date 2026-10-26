"""
Human-readable explanation generator.
Translates technical SHAP/LIME feature attributions into natural language explanations.
"""
from typing import Dict, List, Any
import pandas as pd

# Human-readable rule templates for feature attributions
FEATURE_EXPLANATION_TEMPLATES = {
    "SubdomainLevel": {
        "phishing": "The website uses multiple nested subdomains ({val:.0f} levels), a frequent pattern in domain-spoofing attacks.",
        "legitimate": "The domain structure is standard with {val:.0f} subdomains."
    },
    "UrlLength": {
        "phishing": "The URL is unusually long ({val:.0f} characters), typical of phishing URLs concealing token payloads or redirect targets.",
        "legitimate": "The URL length ({val:.0f} characters) is within normal parameters."
    },
    "NoHttps": {
        "phishing": "The connection uses unencrypted HTTP instead of secure HTTPS, exposing traffic to tampering.",
        "legitimate": "The website uses standard HTTPS encryption."
    },
    "NumDots": {
        "phishing": "The URL contains {val:.0f} dot separators, indicating excessive domain fragmentation.",
        "legitimate": "The dot count in the URL ({val:.0f}) is standard for genuine websites."
    },
    "NumDash": {
        "phishing": "The URL contains {val:.0f} hyphens/dashes, commonly used to craft deceptive lookalike domain names.",
        "legitimate": "Hyphen usage in the URL is low ({val:.0f})."
    },
    "NumDashInHostname": {
        "phishing": "The hostname contains {val:.0f} hyphens, often used to simulate brand names (e.g. 'paypal-update').",
        "legitimate": "The hostname does not contain excessive hyphens."
    },
    "AtSymbol": {
        "phishing": "The URL contains an '@' character, which causes browsers to ignore preceding credentials and redirect to a spoofed host.",
        "legitimate": "No '@' credential symbol present."
    },
    "IpAddress": {
        "phishing": "The URL uses a raw IP address instead of a registered domain name, bypassing DNS reputation checks.",
        "legitimate": "The URL uses a standard registered domain name."
    },
    "DomainInSubdomains": {
        "phishing": "A recognized domain or brand name is placed inside a subdomain to mimic an authentic service.",
        "legitimate": "Subdomain names do not contain misleading domain tokens."
    },
    "DomainInPaths": {
        "phishing": "A trusted brand keyword is embedded in the URL path to trick users.",
        "legitimate": "Path structure does not contain suspicious embedded brand tokens."
    },
    "NumSensitiveWords": {
        "phishing": "The URL contains security/banking sensitive keywords ('login', 'verify', 'account'), common in phishing bait.",
        "legitimate": "No high-risk sensitive keywords detected in URL path."
    },
    "EmbeddedBrandName": {
        "phishing": "A major brand name is embedded in the URL while the host domain is unregistered to that brand.",
        "legitimate": "Brand name usage aligns with the authentic host domain."
    },
    "PctExtHyperlinks": {
        "phishing": "A large percentage ({val:.0%}) of hyperlinks point to external domains, common in cloned phishing landing pages.",
        "legitimate": "Internal-to-external hyperlink ratio is balanced."
    },
    "PctExtResourceUrls": {
        "phishing": "Over {val:.0%} of page resources (images/scripts) are loaded from external origins rather than the host.",
        "legitimate": "Webpage resources are properly hosted on first-party infrastructure."
    },
    "InsecureForms": {
        "phishing": "The page includes form fields submitting sensitive credentials over unencrypted HTTP.",
        "legitimate": "Form submissions utilize secure encrypted endpoints."
    },
    "ExtFormAction": {
        "phishing": "The submission form transmits entered data to an external, third-party server.",
        "legitimate": "Form action posts to the legitimate first-party domain."
    },
    "AbnormalFormAction": {
        "phishing": "The form action is abnormal (empty, javascript:, or about:blank), indicating client-side data harvesting.",
        "legitimate": "Form action uses a valid submission target."
    },
    "PctNullSelfRedirectHyperlinks": {
        "phishing": "A high fraction ({val:.0%}) of page links are empty or null redirects ('#', javascript:void(0)), typical of dummy cloned sites.",
        "legitimate": "Hyperlinks lead to functional destination endpoints."
    },
    "IframeOrFrame": {
        "phishing": "The webpage utilizes hidden or borderless iframes, frequently employed for clickjacking or invisible overlays.",
        "legitimate": "No suspicious iframe overlays detected."
    },
    "RightClickDisabled": {
        "phishing": "The website deliberately disables right-click context menus to hinder source code inspection.",
        "legitimate": "Standard browser context menus remain accessible."
    },
    "PopUpWindow": {
        "phishing": "The webpage triggers automated popup windows to prompt for user credentials.",
        "legitimate": "No suspicious automated popup prompts detected."
    },
    "MissingTitle": {
        "phishing": "The webpage lacks an HTML title tag, characteristic of hurriedly constructed phishing kits.",
        "legitimate": "Webpage includes an authentic HTML title."
    },
    "RandomString": {
        "phishing": "The URL contains high-entropy randomized strings, commonly used in one-time phishing campaign links.",
        "legitimate": "URL path uses standard human-readable naming."
    }
}

class ExplanationGenerator:
    """
    Generates human-readable security explanations from SHAP attributions and feature states.
    """
    def __init__(self, shap_service=None):
        from .shap_explainer import ShapExplainerService
        self.shap_service = shap_service or ShapExplainerService()

    def generate_explanation(self, df_features: pd.DataFrame, is_phishing: bool) -> Dict[str, Any]:
        """
        Builds clear human-readable factors and technical metrics.
        """
        shap_res = self.shap_service.explain(df_features, top_k=6)
        top_factors = shap_res.get("top_factors", [])
        
        human_reasons = []
        technical_factors = []
        
        for factor in top_factors:
            feat_name = factor["feature"]
            feat_val = factor["value"]
            impact = factor["impact"]
            shap_val = factor["shap_value"]
            
            # Look up human-readable description
            template_dict = FEATURE_EXPLANATION_TEMPLATES.get(feat_name, {})
            explanation_text = ""
            
            if impact in template_dict:
                try:
                    explanation_text = template_dict[impact].format(val=feat_val)
                except Exception:
                    explanation_text = f"Feature '{feat_name}' (value: {feat_val}) influenced the result towards {impact}."
            else:
                if impact == "phishing":
                    explanation_text = f"The attribute '{feat_name}' (value: {feat_val}) increased the estimated phishing risk."
                else:
                    explanation_text = f"The attribute '{feat_name}' (value: {feat_val}) supported a legitimate website profile."

            human_reasons.append({
                "factor": feat_name,
                "text": explanation_text,
                "impact": impact,
                "importance": abs(shap_val)
            })
            
            technical_factors.append({
                "feature": feat_name,
                "value": feat_val,
                "shap_attribution": shap_val,
                "direction": "+Phishing" if shap_val > 0 else "-Legitimate",
                "magnitude": abs(shap_val)
            })

        # Ensure at least 3 reasons are generated
        if len(human_reasons) < 3:
            feat_row = df_features.iloc[0].to_dict()
            if is_phishing:
                if feat_row.get("NoHttps", 0) == 1 and not any(r["factor"] == "NoHttps" for r in human_reasons):
                    human_reasons.append({
                        "factor": "NoHttps",
                        "text": "The website does not utilize HTTPS encryption.",
                        "impact": "phishing",
                        "importance": 0.5
                    })
                if feat_row.get("SubdomainLevel", 0) >= 2 and not any(r["factor"] == "SubdomainLevel" for r in human_reasons):
                    human_reasons.append({
                        "factor": "SubdomainLevel",
                        "text": "The URL uses multiple nested subdomains.",
                        "impact": "phishing",
                        "importance": 0.4
                    })
                if feat_row.get("UrlLength", 0) > 70 and not any(r["factor"] == "UrlLength" for r in human_reasons):
                    human_reasons.append({
                        "factor": "UrlLength",
                        "text": "The overall URL string is unusually long.",
                        "impact": "phishing",
                        "importance": 0.3
                    })

        return {
            "summary_reasons": human_reasons[:5],
            "technical_factors": technical_factors,
            "base_value": shap_res.get("base_value", 0.0),
            "disclaimer": "This explanation describes the model's feature attribution reasoning. It does not provide an absolute guarantee of website safety."
        }
