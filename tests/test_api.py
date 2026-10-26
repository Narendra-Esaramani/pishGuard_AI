"""
Unit tests for REST API endpoints including Developer Diagnostics.
"""
import sys
from pathlib import Path
import json
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_api_model_info(client):
    res = client.get("/api/model-info")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "model_metadata" in data

def test_api_analyze_valid_url(client):
    res = client.post(
        "/api/analyze",
        data=json.dumps({"url": "https://www.google.com"}),
        content_type="application/json"
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "data" in data
    assert "risk_score" in data["data"]
    assert "data_quality" in data["data"]

def test_api_diagnostic_endpoint(client):
    res = client.post(
        "/api/diagnostic",
        data=json.dumps({"url": "https://personasenlinea.net/"}),
        content_type="application/json"
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "diagnostic_report" in data
    assert "feature_completeness" in data["diagnostic_report"]

def test_api_analyze_invalid_payload(client):
    res = client.post(
        "/api/analyze",
        data=json.dumps({"url": ""}),
        content_type="application/json"
    )
    assert res.status_code == 400

def test_api_robustness_test(client):
    res = client.post(
        "/api/robustness-test",
        data=json.dumps({"url": "https://example.com"}),
        content_type="application/json"
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "variants" in data["data"]
    assert len(data["data"]["variants"]) == 5

def test_api_feedback(client):
    res = client.post(
        "/api/feedback",
        data=json.dumps({
            "url": "https://sample.com",
            "predicted_label": "legitimate",
            "probability": 0.1,
            "risk_score": 10,
            "user_feedback": "Correct"
        }),
        content_type="application/json"
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"

def test_api_history(client):
    res = client.get("/api/history")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "history" in data
