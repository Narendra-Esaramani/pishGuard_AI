"""
Safe, passive HTML/DOM feature extraction module.
Fetches webpage content with SSRF protection, size caps, and strict timeouts.
Parses forms, scripts, links, frames, and favicons to extract 16 content features and RT derivations.
"""
import re
from urllib.parse import urlparse, urljoin
from collections import Counter
from typing import Dict, Any, Tuple, Optional

import requests
from bs4 import BeautifulSoup

from config import REQUEST_TIMEOUT_SECONDS, MAX_HTML_BODY_BYTES, USER_AGENT
from .domain_features import is_ssrf_risk_host
from .feature_schema import (
    compute_pct_ext_resource_urls_rt,
    compute_abnormal_ext_form_action_r,
    compute_ext_meta_script_link_rt,
    compute_pct_ext_null_self_redirect_rt
)

def fetch_html_safely(url: str) -> Tuple[Optional[str], bool, str]:
    """
    Safely downloads webpage HTML using passive GET with SSRF guards and size limits.
    Returns: (html_text, success_flag, error_or_status_message)
    """
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str
        
    parsed = urlparse(url_str)
    hostname = parsed.netloc.split(":")[0].lower()
    
    if is_ssrf_risk_host(hostname):
        return None, False, "Blocked: Target host is in private/loopback address range (SSRF guard)."
        
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    
    try:
        response = requests.get(
            url_str,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
            stream=True,
            allow_redirects=True,
            verify=False  # Passive analysis: inspect self-signed/invalid SSL sites as well
        )
        
        # Read with size cap
        content_bytes = bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            content_bytes.extend(chunk)
            if len(content_bytes) > MAX_HTML_BODY_BYTES:
                break
                
        # Decode safely
        encoding = response.encoding if response.encoding else "utf-8"
        try:
            html_text = content_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = content_bytes.decode("utf-8", errors="replace")
            
        return html_text, True, "HTML fetched successfully."
        
    except requests.exceptions.Timeout:
        return None, False, "Connection timed out during HTML retrieval."
    except requests.exceptions.SSLError:
        return None, False, "SSL/TLS handshake failure during HTML retrieval."
    except requests.exceptions.ConnectionError:
        return None, False, "Target website unreachable or refused connection."
    except Exception as e:
        return None, False, f"Passive fetch skipped: {str(e)}"

def extract_html_features_from_soup(soup: BeautifulSoup, page_url: str) -> Dict[str, float]:
    """
    Extracts all 16 DOM and content features from a BeautifulSoup object.
    """
    parsed_page = urlparse(page_url)
    page_host = parsed_page.netloc.split(":")[0].lower()
    page_scheme = parsed_page.scheme.lower()
    
    # 1. PctExtHyperlinks & PctNullSelfRedirectHyperlinks
    a_tags = soup.find_all("a", href=True)
    total_a = len(a_tags)
    ext_a_count = 0
    null_self_a_count = 0
    external_domains = []
    
    for a in a_tags:
        href = str(a["href"]).strip()
        if not href or href == "#" or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            null_self_a_count += 1
            continue
            
        full_url = urljoin(page_url, href)
        parsed_link = urlparse(full_url)
        link_host = parsed_link.netloc.split(":")[0].lower()
        
        if link_host and link_host != page_host:
            ext_a_count += 1
            external_domains.append(link_host)
        elif full_url == page_url or parsed_link.path == parsed_page.path:
            null_self_a_count += 1
            
    pct_ext_hyperlinks = (ext_a_count / total_a) if total_a > 0 else 0.0
    pct_null_self_redirect = (null_self_a_count / total_a) if total_a > 0 else 0.0
    
    # FrequentDomainNameMismatch
    frequent_domain_mismatch = 0
    if external_domains:
        most_common_domain, count = Counter(external_domains).most_common(1)[0]
        if most_common_domain != page_host and (count / total_a) > 0.4:
            frequent_domain_mismatch = 1

    # 2. PctExtResourceUrls (img, script, link, video, audio, embed with src or href)
    candidate_res_tags = soup.find_all(["img", "script", "link", "video", "audio", "embed"])
    valid_res_tags = [tag for tag in candidate_res_tags if tag.get("src") or tag.get("href")]
    total_res = len(valid_res_tags)
    ext_res_count = 0
    
    meta_script_link_tags = [tag for tag in soup.find_all(["meta", "script", "link"]) if tag.get("src") or tag.get("href")]
    ext_meta_script_count = 0
    
    for tag in valid_res_tags:
        src = tag.get("src") or tag.get("href")
        if src:
            src_str = str(src).strip()
            full_res = urljoin(page_url, src_str)
            res_host = urlparse(full_res).netloc.split(":")[0].lower()
            if res_host and res_host != page_host:
                ext_res_count += 1
                
    for tag in meta_script_link_tags:
        src = tag.get("src") or tag.get("href")
        if src:
            src_str = str(src).strip()
            full_res = urljoin(page_url, src_str)
            res_host = urlparse(full_res).netloc.split(":")[0].lower()
            if res_host and res_host != page_host:
                ext_meta_script_count += 1
                
    pct_ext_resource_urls = (ext_res_count / total_res) if total_res > 0 else 0.0
    ext_meta_script_ratio = (ext_meta_script_count / len(meta_script_link_tags)) if meta_script_link_tags else 0.0

    # 3. ExtFavicon
    ext_favicon = 0
    favicon_tag = soup.find("link", rel=lambda x: x and "icon" in str(x).lower())
    if favicon_tag and favicon_tag.get("href"):
        fav_url = urljoin(page_url, str(favicon_tag["href"]).strip())
        fav_host = urlparse(fav_url).netloc.split(":")[0].lower()
        if fav_host and fav_host != page_host:
            ext_favicon = 1

    # 4. Form features
    forms = soup.find_all("form")
    insecure_forms = 0
    relative_form_action = 0
    ext_form_action = 0
    abnormal_form_action = 0
    images_only_in_form = 0
    submit_to_email = 0
    
    for form in forms:
        action = str(form.get("action", "")).strip()
        if not action or action == "#" or action.lower() == "about:blank" or action.lower().startswith("javascript:"):
            abnormal_form_action = 1
        elif action.lower().startswith("mailto:"):
            submit_to_email = 1
            abnormal_form_action = 1
        else:
            full_action = urljoin(page_url, action)
            parsed_action = urlparse(full_action)
            action_host = parsed_action.netloc.split(":")[0].lower()
            
            if parsed_action.scheme.lower() == "http" and page_scheme == "https":
                insecure_forms = 1
                
            if action.startswith(("/", "./", "../")) or not parsed_action.netloc:
                relative_form_action = 1
            elif action_host and action_host != page_host:
                ext_form_action = 1
                
        # Check if form only has image inputs
        inputs = form.find_all("input")
        text_inputs = [i for i in inputs if i.get("type", "text").lower() in ("text", "password", "email", "number", "tel")]
        img_inputs = [i for i in inputs if i.get("type", "").lower() == "image"]
        if inputs and len(img_inputs) > 0 and len(text_inputs) == 0:
            images_only_in_form = 1

    # 5. JavaScript inspection (FakeLinkInStatusBar, RightClickDisabled, PopUpWindow, SubmitInfoToEmail)
    scripts_text = " ".join([script.get_text() for script in soup.find_all("script")])
    body_str = str(soup)
    
    fake_link_in_status_bar = 1 if ("window.status" in scripts_text or "window.status" in body_str) else 0
    right_click_disabled = 1 if ("event.button == 2" in scripts_text or "contextmenu" in scripts_text or "oncontextmenu=\"return false\"" in body_str) else 0
    pop_up_window = 1 if ("window.open(" in scripts_text or "prompt(" in scripts_text) else 0
    if "mailto:" in scripts_text or "mailto:" in body_str:
        submit_to_email = 1

    # 6. IframeOrFrame
    iframes = soup.find_all(["iframe", "frame"])
    iframe_or_frame = 0
    for frame in iframes:
        style = str(frame.get("style", "")).lower()
        width = str(frame.get("width", "")).lower()
        height = str(frame.get("height", "")).lower()
        frameborder = str(frame.get("frameborder", "")).lower()
        if "display:none" in style or "visibility:hidden" in style or width == "0" or height == "0" or frameborder == "0":
            iframe_or_frame = 1
            break
        elif len(iframes) > 0:
            iframe_or_frame = 1

    # 7. MissingTitle
    title_tag = soup.find("title")
    missing_title = 0 if (title_tag and title_tag.get_text().strip()) else 1

    # Rule Thresholds
    pct_ext_resource_urls_rt = compute_pct_ext_resource_urls_rt(pct_ext_resource_urls)
    abnormal_ext_form_action_r = compute_abnormal_ext_form_action_r(abnormal_form_action, ext_form_action)
    ext_meta_script_link_rt = compute_ext_meta_script_link_rt(ext_meta_script_ratio)
    pct_ext_null_self_redirect_rt = compute_pct_ext_null_self_redirect_rt(pct_null_self_redirect)

    return {
        "PctExtHyperlinks": float(pct_ext_hyperlinks),
        "PctExtResourceUrls": float(pct_ext_resource_urls),
        "ExtFavicon": float(ext_favicon),
        "InsecureForms": float(insecure_forms),
        "RelativeFormAction": float(relative_form_action),
        "ExtFormAction": float(ext_form_action),
        "AbnormalFormAction": float(abnormal_form_action),
        "PctNullSelfRedirectHyperlinks": float(pct_null_self_redirect),
        "FrequentDomainNameMismatch": float(frequent_domain_mismatch),
        "FakeLinkInStatusBar": float(fake_link_in_status_bar),
        "RightClickDisabled": float(right_click_disabled),
        "PopUpWindow": float(pop_up_window),
        "SubmitInfoToEmail": float(submit_to_email),
        "IframeOrFrame": float(iframe_or_frame),
        "MissingTitle": float(missing_title),
        "ImagesOnlyInForm": float(images_only_in_form),
        "PctExtResourceUrlsRT": float(pct_ext_resource_urls_rt),
        "AbnormalExtFormActionR": float(abnormal_ext_form_action_r),
        "ExtMetaScriptLinkRT": float(ext_meta_script_link_rt),
        "PctExtNullSelfRedirectHyperlinksRT": float(pct_ext_null_self_redirect_rt)
    }

def extract_html_features(url: str, html_content: Optional[str] = None) -> Tuple[Dict[str, float], bool, str]:
    """
    Main entry point for HTML feature extraction.
    If html_content is provided, parses directly. Otherwise performs safe fetch.
    Returns: (features_dict, html_analyzed_flag, status_message)
    """
    if html_content is None:
        html_text, success, msg = fetch_html_safely(url)
    else:
        html_text, success, msg = html_content, True, "Custom HTML content provided."
        
    if not success or not html_text:
        return {}, False, msg
        
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        features = extract_html_features_from_soup(soup, url)
        return features, True, "HTML features extracted successfully."
    except Exception as e:
        return {}, False, f"HTML parsing error: {str(e)}"
