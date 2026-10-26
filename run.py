"""
Application Runner Entrypoint.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import HOST, PORT, DEBUG
from app.app import create_app

app = create_app()

if __name__ == "__main__":
    print("=" * 70)
    print("   PHISHGUARD AI — ENHANCED PHISHING DETECTION SYSTEM")
    print(f"   Server running at http://{HOST}:{PORT}")
    print("=" * 70)
    app.run(host=HOST, port=PORT, debug=DEBUG)
