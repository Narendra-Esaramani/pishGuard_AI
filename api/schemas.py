"""
API request validation and response schema helpers.
"""
import re
from typing import Dict, Any, Tuple, Optional
from urllib.parse import urlparse

def validate_url_request(data: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Validates that request JSON contains a valid non-empty URL string.
    Returns: (url_string, error_message)
    """
    if not isinstance(data, dict):
        return None, "Request body must be a valid JSON object."
        
    url = data.get("url")
    if not url or not isinstance(url, str) or not url.strip():
        return None, "Missing or empty 'url' field in request body."
        
    url_str = url.strip()
    if len(url_str) > 2048:
        return None, "URL length exceeds maximum allowable limit (2048 characters)."
        
    # Basic URL structural validation
    if not re.match(r"^[a-zA-Z0-9+.-]+://", url_str):
        # Auto-prefix http:// if omitted for user convenience
        url_str = "http://" + url_str

    parsed = urlparse(url_str)
    if not parsed.netloc:
        return None, "Invalid URL format: Unable to extract hostname."
        
    return url_str, None

def validate_feedback_request(data: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Validates feedback submission payload."""
    if not isinstance(data, dict):
        return None, "Request body must be a valid JSON object."
        
    url = data.get("url")
    if not url or not isinstance(url, str):
        return None, "Missing mandatory 'url' string."
        
    user_feedback = data.get("user_feedback")
    if user_feedback not in ("Correct", "Incorrect"):
        return None, "Field 'user_feedback' must be either 'Correct' or 'Incorrect'."
        
    return {
        "url": url.strip(),
        "predicted_label": str(data.get("predicted_label", "unknown")),
        "probability": float(data.get("probability", 0.5)),
        "risk_score": int(data.get("risk_score", 50)),
        "user_feedback": user_feedback,
        "actual_label": data.get("actual_label", "unknown"),
        "comments": str(data.get("comments", ""))
    }, None
