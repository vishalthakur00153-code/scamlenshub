import pytest
from app.engine import analyze_message, analyze_url
from app.models import MessageScanRequest, UrlScanRequest


def test_message_whitespace_handling():
    padded_text = "   \n\t Congratulations! You have won $50,000 lottery cash prize! \n\t  "
    result = analyze_message(padded_text)
    assert result.risk_level in ["Needs Verification", "Suspicious"]
    assert not result.analyzed_preview.startswith(" ")


def test_url_whitespace_handling():
    padded_url = "   \n https://paypal-security.xyz/update   "
    result = analyze_url(padded_url)
    assert result.risk_level in ["Needs Verification", "Suspicious"]
    assert not result.analyzed_preview.startswith(" ")


def test_url_without_scheme_handling():
    bare_url = "paypal-security-verification.xyz/login"
    result = analyze_url(bare_url)
    assert result.risk_level in ["Needs Verification", "Suspicious"]
    indicator_ids = [i.id for i in result.indicators]
    assert any("URL_BRAND" in ind_id for ind_id in indicator_ids)


def test_combined_multi_indicator_message():
    text = (
        "URGENT: Your account has been suspended! You have been selected for a high paying part-time job. "
        "Pay Rs. 3,000 security deposit immediately. Share your OTP and contact manager on Telegram @JobAlerts."
    )
    result = analyze_message(text)
    assert result.risk_level == "Suspicious"
    assert result.risk_score >= 80
    assert len(result.indicators) >= 3


def test_model_validation_rejects_empty_string():
    with pytest.raises(Exception):
        MessageScanRequest(text="   ")

    with pytest.raises(Exception):
        UrlScanRequest(url="   ")


def test_model_validation_accepts_valid_string():
    req = MessageScanRequest(text="Valid test message for scanning")
    assert req.text == "Valid test message for scanning"

    url_req = UrlScanRequest(url="https://example.com")
    assert url_req.url == "https://example.com"
