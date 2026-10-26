"""
Evidence-Synthesis Layer.
Separates ML prediction, URL syntax signals, domain availability/telemetry,
HTML DOM evidence, and evidence confidence.
Detects contradictory signals and incomplete evidence to enforce
SUSPICIOUS / NEEDS REVIEW verdicts instead of forcing false SAFE or false PHISHING decisions.
"""
from typing import Dict, Any, List, Tuple
import pandas as pd

class EvidenceSynthesisEngine:
    """
    Synthesizes independent evidence channels and detects contradictions
    between URL lexical signals, domain reputation, and HTML telemetry.
    """
    
    @staticmethod
    def synthesize_channels(
        ml_prediction: int,
        phishing_probability: float,
        df_features: pd.DataFrame,
        extraction_meta: Dict[str, Any],
        diag_meta: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluates 4 independent evidence channels and computes concordance.
        """
        feat_row = df_features.iloc[0].to_dict()
        domain_meta = extraction_meta.get("domain_metadata", {})
        ood_info = diag_meta.get("ood_info", {})
        html_analyzed = extraction_meta.get("html_analysis", False)
        
        # 1. URL Syntax Channel (Score 0-100)
        url_risk_points = 0
        url_signals = []
        
        if feat_row.get("SubdomainLevel", 0) >= 3:
            url_risk_points += 25
            url_signals.append(f"High subdomain depth ({int(feat_row['SubdomainLevel'])} levels)")
        elif feat_row.get("SubdomainLevel", 0) == 2:
            url_risk_points += 10
            url_signals.append("Multiple subdomains")
            
        if feat_row.get("UrlLength", 0) > 85:
            url_risk_points += 20
            url_signals.append(f"Unusually long URL ({int(feat_row['UrlLength'])} chars)")
            
        if feat_row.get("NumSensitiveWords", 0) >= 1:
            url_risk_points += 20
            url_signals.append(f"Contains security/sensitive keywords ({int(feat_row['NumSensitiveWords'])})")
            
        if feat_row.get("NoHttps", 0) == 1:
            url_risk_points += 15
            url_signals.append("Insecure HTTP protocol (no encryption)")
            
        if feat_row.get("DomainInSubdomains", 0) == 1 or feat_row.get("EmbeddedBrandName", 0) == 1:
            url_risk_points += 30
            url_signals.append("Brand name camouflage in subdomain/path")
            
        if feat_row.get("IpAddress", 0) == 1:
            url_risk_points += 35
            url_signals.append("Raw numeric IP address hostname")
            
        url_channel_state = "SUSPICIOUS" if url_risk_points >= 40 else ("ELEVATED" if url_risk_points >= 20 else "CLEAN")

        # 2. Domain Telemetry Channel
        dns_ok = domain_meta.get("dns_resolved", False)
        https_ok = domain_meta.get("https_available", False)
        is_ip = domain_meta.get("is_ip_address", False)
        
        domain_signals = []
        if not is_ip:
            if dns_ok:
                domain_signals.append("Domain active and resolvable via standard DNS")
            else:
                domain_signals.append("Domain failed DNS resolution (unresolvable / offline / taken down)")
                
            if https_ok:
                domain_signals.append("Valid HTTPS SSL handshake confirmed")
            else:
                domain_signals.append("No active HTTPS handshake response")
                
        domain_healthy = bool(dns_ok or is_ip)
        domain_channel_state = "HEALTHY" if (dns_ok and https_ok) else ("OFFLINE/UNRESOLVED" if not dns_ok else "DEGRADED")

        # 3. HTML Content Channel
        html_signals = []
        if html_analyzed:
            if feat_row.get("InsecureForms", 0) == 1:
                html_signals.append("Insecure password/form submission over HTTP")
            if feat_row.get("AbnormalFormAction", 0) == 1:
                html_signals.append("Abnormal/empty form action detected")
            if feat_row.get("PctExtHyperlinks", 0) > 0.6:
                html_signals.append(f"High external link ratio ({feat_row.get('PctExtHyperlinks', 0):.0%})")
            if not html_signals:
                html_signals.append("Live webpage DOM inspected; normal structural layout")
            html_channel_state = "THREAT_DETECTED" if (feat_row.get("InsecureForms", 0) or feat_row.get("AbnormalFormAction", 0)) else "ACTIVE_CLEAN"
        else:
            html_signals.append(extraction_meta.get("html_message", "HTML live inspection unavailable (offline/unreachable)."))
            html_channel_state = "UNAVAILABLE"

        # 4. ML Channel
        ml_channel_state = "PHISHING" if phishing_probability >= 0.70 else ("LEGITIMATE" if phishing_probability <= 0.30 else "BORDERLINE")

        # 5. Detect Contradictions & Evidence Insufficiency
        is_contradictory = False
        contradiction_reasons = []
        
        # Contradiction Case 1: Clean URL syntax, but Domain DNS failed or site is dead/offline
        if url_channel_state == "CLEAN" and domain_channel_state == "OFFLINE/UNRESOLVED":
            is_contradictory = True
            contradiction_reasons.append(
                "URL syntax appears clean, but domain failed DNS resolution and live content cannot be verified."
            )
            
        # Contradiction Case 2: ML model predicts Legitimate, but Domain is dead or HTML channel unavailable with sensitive keywords
        if ml_channel_state == "LEGITIMATE" and (domain_channel_state == "OFFLINE/UNRESOLVED" or url_risk_points >= 20):
            is_contradictory = True
            contradiction_reasons.append(
                "ML model probability is low, but domain telemetry indicates unresolvable host or keyword anomalies."
            )
            
        # Contradiction Case 3: High URL risk points, but Domain is a verified healthy top-level domain with valid SSL
        if url_channel_state == "SUSPICIOUS" and domain_channel_state == "HEALTHY" and ml_channel_state == "LEGITIMATE":
            is_contradictory = True
            contradiction_reasons.append(
                "URL contains structural parameters (e.g. deep path segments), but domain telemetry confirms authentic registered host."
            )

        # 6. Synthesized Final Verdict
        if is_contradictory or (not html_analyzed and not dns_ok):
            # Enforce SUSPICIOUS / NEEDS REVIEW when evidence is contradictory or incomplete
            synthesized_verdict = "SUSPICIOUS (NEEDS REVIEW)"
            synthesized_risk_level = "SUSPICIOUS"
            synthesized_badge = "warning"
            # Calibrate risk score into 35-55 buffer
            if phishing_probability < 0.35:
                synthesized_risk_score = 42
            elif phishing_probability > 0.65:
                synthesized_risk_score = 58
            else:
                synthesized_risk_score = int(round(phishing_probability * 100))
                
            evidence_verdict_rationale = (
                "Contradictory or incomplete evidence detected between URL syntax, domain availability, and live content. "
                "The system avoids forcing a definitive Safe or Phishing verdict and flags this website for manual review."
            )
        elif phishing_probability >= 0.70 or url_risk_points >= 50 or html_channel_state == "THREAT_DETECTED":
            synthesized_verdict = "LIKELY PHISHING"
            synthesized_risk_level = "HIGH RISK"
            synthesized_badge = "danger"
            synthesized_risk_score = max(70, int(round(phishing_probability * 100)))
            evidence_verdict_rationale = "Multiple concordant evidence channels confirm high phishing risk."
        elif phishing_probability <= 0.30 and domain_healthy and (html_analyzed or url_channel_state == "CLEAN"):
            synthesized_verdict = "LIKELY LEGITIMATE"
            synthesized_risk_level = "SAFE"
            synthesized_badge = "safe"
            synthesized_risk_score = min(30, int(round(phishing_probability * 100)))
            evidence_verdict_rationale = "URL syntax and domain telemetry concordantly indicate legitimate operation."
        else:
            synthesized_verdict = "SUSPICIOUS (NEEDS REVIEW)"
            synthesized_risk_level = "SUSPICIOUS"
            synthesized_badge = "warning"
            synthesized_risk_score = max(31, min(69, int(round(phishing_probability * 100))))
            evidence_verdict_rationale = "Moderate risk indicators detected across available telemetry channels."

        return {
            "synthesized_verdict": synthesized_verdict,
            "synthesized_risk_level": synthesized_risk_level,
            "synthesized_badge": synthesized_badge,
            "synthesized_risk_score": synthesized_risk_score,
            "evidence_verdict_rationale": evidence_verdict_rationale,
            "is_contradictory": is_contradictory,
            "contradiction_reasons": contradiction_reasons,
            "channels": {
                "ml_channel": {
                    "state": ml_channel_state,
                    "calibrated_probability": round(phishing_probability, 4),
                    "confidence": diag_meta.get("confidence", "MODERATE")
                },
                "url_channel": {
                    "state": url_channel_state,
                    "risk_points": url_risk_points,
                    "signals": url_signals
                },
                "domain_channel": {
                    "state": domain_channel_state,
                    "dns_resolved": dns_ok,
                    "https_available": https_ok,
                    "signals": domain_signals
                },
                "html_channel": {
                    "state": html_channel_state,
                    "is_live": html_analyzed,
                    "signals": html_signals
                }
            }
        }

    @staticmethod
    def synthesize_channels_experimental(
        ml_prediction: int,
        phishing_probability: float,
        df_features: pd.DataFrame,
        extraction_meta: Dict[str, Any],
        diag_meta: Dict[str, Any],
        decision_threshold: float = 0.65
    ) -> Dict[str, Any]:
        """
        Experimental Evidence-Synthesis Layer.
        Evaluates hostname structure, registered-domain telemetry, path depth,
        deceptive brand placement, and feature availability together without
        relying solely on lexical syntax or hardcoded domains.
        """
        feat_row = df_features.iloc[0].to_dict()
        domain_meta = extraction_meta.get("domain_metadata", {})
        ood_info = diag_meta.get("ood_info", {})
        html_analyzed = extraction_meta.get("html_analysis", False)

        # 1. Hostname Structural Integrity
        dns_ok = domain_meta.get("dns_resolved", False)
        https_ok = domain_meta.get("https_available", False)
        is_ip = domain_meta.get("is_ip_address", False)
        is_high_risk_tld = domain_meta.get("is_high_risk_tld", False)
        brand_conflict = domain_meta.get("brand_in_subdomain_conflict", False)
        subdomain_level = int(feat_row.get("SubdomainLevel", 0))
        dash_in_host = int(feat_row.get("NumDashInHostname", 0))
        no_https = int(feat_row.get("NoHttps", 0))
        path_level = int(feat_row.get("PathLevel", 0))
        num_sensitive = int(feat_row.get("NumSensitiveWords", 0))
        embedded_brand = int(feat_row.get("EmbeddedBrandName", 0))
        path_ratio = domain_meta.get("path_to_hostname_ratio", 0.0)

        hostname_risk_points = 0
        hostname_signals = []

        if is_ip:
            hostname_risk_points += 40
            hostname_signals.append("Raw IP address used as hostname")
        if brand_conflict or (embedded_brand == 1 and subdomain_level >= 2):
            hostname_risk_points += 35
            hostname_signals.append("Brand name camouflage in subdomain structure")
        if subdomain_level >= 3:
            hostname_risk_points += 25
            hostname_signals.append(f"Excessive subdomain depth ({subdomain_level} levels)")
        elif subdomain_level == 2:
            hostname_risk_points += 10
            hostname_signals.append("Multi-level subdomain")
        if dash_in_host >= 2:
            hostname_risk_points += 20
            hostname_signals.append(f"Multiple hyphens in hostname ({dash_in_host})")
        elif dash_in_host == 1:
            hostname_risk_points += 5
        if is_high_risk_tld:
            hostname_risk_points += 20
            hostname_signals.append(f"High-risk suspicious top-level domain (.{domain_meta.get('tld', '')})")
        if not dns_ok and not is_ip:
            hostname_risk_points += 25
            hostname_signals.append("Domain failed standard DNS resolution (unresolvable/inactive)")

        is_clean_hostname = bool(
            hostname_risk_points <= 10 and 
            dns_ok and 
            not is_ip and 
            not brand_conflict and 
            not is_high_risk_tld and 
            dash_in_host == 0
        )

        # 2. Path Complexity vs Deception Assessment
        path_signals = []
        is_deep_hierarchical_path = bool(path_level >= 2 or (path_level >= 1 and path_ratio >= 0.7))
        
        if is_deep_hierarchical_path:
            path_signals.append(f"Hierarchical deep resource path (depth={path_level}, ratio={path_ratio:.1f})")

            
        if num_sensitive >= 1:
            path_signals.append(f"Sensitive credential/security keywords detected in URL ({num_sensitive})")

        # 3. HTML Telemetry
        html_signals = []
        html_threat = False
        if html_analyzed:
            if feat_row.get("InsecureForms", 0) == 1:
                html_threat = True
                html_signals.append("Insecure credential form submission over HTTP")
            if feat_row.get("AbnormalFormAction", 0) == 1:
                html_threat = True
                html_signals.append("Abnormal/empty form action detected")
            if not html_signals:
                html_signals.append("Live webpage DOM inspected; normal layout")
            html_channel_state = "THREAT_DETECTED" if html_threat else "ACTIVE_CLEAN"
        else:
            html_signals.append("HTML inspection offline/unavailable; relying on structural and telemetry synthesis.")
            html_channel_state = "UNAVAILABLE"

        # 4. Evidence-Synthesis & Contradiction Resolution
        is_contradictory = False
        contradiction_reasons = []

        # Contradiction: Clean hostname with valid DNS and HTTPS, but tree model outputs high probability purely due to path length/depth
        if is_clean_hostname and is_deep_hierarchical_path and phishing_probability >= 0.50 and not html_threat:
            is_contradictory = True
            contradiction_reasons.append(
                "High model probability is driven primarily by deep path hierarchy on a structurally clean registered domain."
            )

        # 5. Verdict Determination Matrix
        # Case A: Critical Threats (Severe brand spoofing, raw IP, live HTML threats, or high hostname deception)
        if html_threat or brand_conflict or (is_ip and num_sensitive >= 1) or hostname_risk_points >= 50 or (phishing_probability >= decision_threshold and not is_clean_hostname):
            synthesized_verdict = "LIKELY PHISHING"
            synthesized_risk_level = "HIGH RISK"
            synthesized_badge = "danger"
            synthesized_risk_score = max(70, min(99, int(round(max(phishing_probability, 0.70) * 100))))
            evidence_verdict_rationale = "High-risk deception signals concordantly confirmed by hostname and telemetry channels."

        # Case B: Clean Registered Domain with Deep Path (Documentation, scientific articles, developer portals)
        elif is_clean_hostname and is_deep_hierarchical_path and not html_threat:
            if num_sensitive >= 1 and not html_analyzed:
                # Sensitive keyword in path (e.g. /security or /help) without HTML confirmation
                synthesized_verdict = "SUSPICIOUS (NEEDS REVIEW)"
                synthesized_risk_level = "SUSPICIOUS"
                synthesized_badge = "warning"
                synthesized_risk_score = 45
                evidence_verdict_rationale = (
                    "URL contains security-related path keywords on an authentic registered domain. "
                    "In the absence of live HTML analysis, the system flags this resource for review."
                )
            else:
                # Standard documentation or nested content on authentic domain
                synthesized_verdict = "LIKELY LEGITIMATE"
                synthesized_risk_level = "SAFE"
                synthesized_badge = "safe"
                synthesized_risk_score = max(5, min(28, int(round(min(phishing_probability, 0.28) * 100))))
                evidence_verdict_rationale = (
                    "Authentic registered domain with hierarchical resource path. "
                    "Lexical path length does not indicate malicious spoofing."
                )

        # Case C: Offline / Unresolvable Domains with Incomplete Evidence
        elif not dns_ok and not is_ip:
            synthesized_verdict = "SUSPICIOUS (NEEDS REVIEW)"
            synthesized_risk_level = "SUSPICIOUS"
            synthesized_badge = "warning"
            synthesized_risk_score = max(42, min(65, int(round(phishing_probability * 100))))
            evidence_verdict_rationale = (
                "Domain is unresolvable or inactive via standard DNS. "
                "Classified as suspicious due to incomplete telemetry."
            )

        # Case D: Standard Probability-based Evaluation
        elif phishing_probability >= decision_threshold:
            synthesized_verdict = "LIKELY PHISHING"
            synthesized_risk_level = "HIGH RISK"
            synthesized_badge = "danger"
            synthesized_risk_score = max(70, int(round(phishing_probability * 100)))
            evidence_verdict_rationale = f"Calibrated model probability exceeds decision threshold ({decision_threshold:.2f})."

        elif phishing_probability <= 0.35 and dns_ok:
            synthesized_verdict = "LIKELY LEGITIMATE"
            synthesized_risk_level = "SAFE"
            synthesized_badge = "safe"
            synthesized_risk_score = min(30, int(round(phishing_probability * 100)))
            evidence_verdict_rationale = "Concordant low risk signals across telemetry and ML channels."

        else:
            synthesized_verdict = "SUSPICIOUS (NEEDS REVIEW)"
            synthesized_risk_level = "SUSPICIOUS"
            synthesized_badge = "warning"
            synthesized_risk_score = max(31, min(69, int(round(phishing_probability * 100))))
            evidence_verdict_rationale = "Moderate risk indicators; telemetry warrants manual review."

        return {
            "synthesized_verdict": synthesized_verdict,
            "synthesized_risk_level": synthesized_risk_level,
            "synthesized_badge": synthesized_badge,
            "synthesized_risk_score": synthesized_risk_score,
            "evidence_verdict_rationale": evidence_verdict_rationale,
            "is_contradictory": is_contradictory,
            "contradiction_reasons": contradiction_reasons,
            "experimental_mode": True,
            "channels": {
                "ml_channel": {
                    "calibrated_probability": round(phishing_probability, 4),
                    "threshold_applied": decision_threshold,
                    "confidence": diag_meta.get("confidence", "MODERATE")
                },
                "hostname_channel": {
                    "is_clean_hostname": is_clean_hostname,
                    "risk_points": hostname_risk_points,
                    "signals": hostname_signals
                },
                "path_channel": {
                    "is_deep_hierarchical_path": is_deep_hierarchical_path,
                    "signals": path_signals
                },
                "domain_channel": {
                    "registered_domain": domain_meta.get("registered_domain", ""),
                    "tld": domain_meta.get("tld", ""),
                    "dns_resolved": dns_ok,
                    "https_available": https_ok
                },
                "html_channel": {
                    "state": html_channel_state,
                    "is_live": html_analyzed,
                    "signals": html_signals
                }
            }
        }

