"""
Robustness report serializer.
"""
from typing import Dict, Any

def format_robustness_report(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """Wraps raw robustness test results with metadata."""
    return raw_results
