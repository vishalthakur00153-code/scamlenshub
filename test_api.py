import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ScamLens"
    assert "stateless" in data["storage"]

    # Also test /health endpoint for Render health checks
    render_health = client.get("/health")
    assert render_health.status_code == 200
    assert render_health.json()["status"] == "healthy"


def test_scan_message_endpoint_suspicious():
    payload = {
        "text": (
            "Congratulations! You have been selected for the Python Developer Internship at Global Tech Innovations. "
            "To confirm your joining and receive your company laptop kit, you are required to deposit a refundable "
            "registration fee of Rs. 2,500. This security deposit will be refunded with your first month stipend."
        )
    }
    response = client.post("/api/scan/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "message"
    assert data["risk_level"] in ["Needs Verification", "Suspicious"]
    assert len(data["indicators"]) > 0
    assert len(data["recommended_actions"]) > 0
    assert len(data["limitations"]) > 0
    assert data["is_definitive_claim"] is False


def test_scan_message_endpoint_legitimate():
    payload = {
        "text": (
            "Hi team, just a reminder that our daily standup is at 10 AM tomorrow in Room 4B. "
            "Please bring your notes on the current release tickets."
        )
    }
    response = client.post("/api/scan/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "Low Concern"
    assert len(data["indicators"]) == 0


def test_scan_message_validation_empty():
    response = client.post("/api/scan/message", json={"text": "   "})
    assert response.status_code == 422


def test_scan_url_endpoint_suspicious():
    payload = {"url": "https://paypal-security-verification.xyz/login/verify-account"}
    response = client.post("/api/scan/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "url"
    assert data["risk_level"] in ["Needs Verification", "Suspicious"]
    assert len(data["indicators"]) > 0


def test_scan_url_endpoint_legitimate():
    payload = {"url": "https://www.google.com"}
    response = client.post("/api/scan/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "Low Concern"


def test_scan_url_validation_empty():
    response = client.post("/api/scan/url", json={"url": " "})
    assert response.status_code == 422


def test_frontend_homepage_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "Think Before You Trust. Scan Before You Pay." in response.text
    assert "ScamLens" in response.text


def test_frontend_static_assets_served():
    css_res = client.get("/styles.css")
    assert css_res.status_code == 200
    assert "var(--bg-main)" in css_res.text

    js_res = client.get("/app.js")
    assert js_res.status_code == 200
    assert "ScamLens Frontend Application Logic" in js_res.text
