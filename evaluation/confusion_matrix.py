"""
Confusion matrix visualization and text formatting.
"""
from typing import Dict, Any

def format_confusion_matrix_text(cm_dict: Dict[str, int]) -> str:
    """Formats confusion matrix as an aligned ASCII table."""
    tn = cm_dict["tn"]
    fp = cm_dict["fp"]
    fn = cm_dict["fn"]
    tp = cm_dict["tp"]
    
    total = tn + fp + fn + tp
    
    return f"""
+-----------------------+-----------------------------+
| Actual / Predicted    | Pred: Legitimate | Pred: Phishing  |
+-----------------------+------------------+-----------------+
| Actual: Legitimate (0)| TN = {tn:<10}  | FP = {fp:<11} |
| Actual: Phishing   (1)| FN = {fn:<10}  | TP = {tp:<11} |
+-----------------------+------------------+-----------------+
Total Evaluated Samples: {total}
"""
