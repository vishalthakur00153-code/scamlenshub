import pytest
from app.engine import analyze_message


def test_suspicious_internship_fee_scam():
    text = (
        "Congratulations! You have been selected for the Data Analyst Internship at TechSpark Solutions. "
        "To confirm your offer and reserve your training kit, you must pay a refundable registration fee "
        "of Rs. 2,000 before joining. This fee will be refunded after your first month stipend."
    )
    result = analyze_message(text)
    assert result.risk_level in ["Needs Verification", "Suspicious"]
    indicator_ids = [i.id for i in result.indicators]
    assert "MSG_UPFRONT_FEE" in indicator_ids
    assert result.risk_score >= 35


def test_suspicious_bank_otp_phishing():
    text = (
        "URGENT: Your State Bank account has been temporarily suspended due to pending KYC verification. "
        "To prevent permanent deactivation, share your 6-digit OTP and card PIN immediately."
    )
    result = analyze_message(text)
    assert result.risk_level == "Suspicious"
    indicator_ids = [i.id for i in result.indicators]
    assert "MSG_CREDENTIAL_OTP" in indicator_ids
    assert "MSG_URGENT_COERCION" in indicator_ids
    assert result.risk_score >= 60


def test_suspicious_lottery_prize_jackpot():
    text = (
        "Congratulations! You have been selected as the lucky winner of the International Mega Jackpot. "
        "You have won $1,000,000 cash reward. Contact claims officer on Telegram @MegaPrizes to claim."
    )
    result = analyze_message(text)
    assert result.risk_level in ["Needs Verification", "Suspicious"]
    indicator_ids = [i.id for i in result.indicators]
    assert "MSG_LOTTERY_PRIZE" in indicator_ids
    assert "MSG_OFF_PLATFORM" in indicator_ids


def test_suspicious_authority_impersonation_courier():
    text = (
        "Customs department clearance alert: Your international parcel has been held due to illegal contraband. "
        "Arrest warrant will be issued unless clearance duty is deposited immediately via crypto bitcoin wallet."
    )
    result = analyze_message(text)
    assert result.risk_level == "Suspicious"
    indicator_ids = [i.id for i in result.indicators]
    assert "MSG_IMPERSONATION_AUTHORITY" in indicator_ids
    assert "MSG_SUSPICIOUS_PAYMENT_METHOD" in indicator_ids


def test_legitimate_interview_invitation():
    text = (
        "Hello Jordan, Thank you for applying for the Software Engineer role at Acme Technologies. "
        "We reviewed your resume and would like to invite you for a 45-minute technical discussion "
        "next Wednesday at 3:00 PM. Please let us know if this time is convenient for you."
    )
    result = analyze_message(text)
    assert result.risk_level == "Low Concern"
    assert result.risk_score < 25
    assert len(result.indicators) == 0


def test_legitimate_shipping_confirmation():
    text = (
        "Your order #48291 has shipped via standard courier! Estimated delivery is Thursday between "
        "10 AM and 2 PM. You can track your shipment status inside your account dashboard."
    )
    result = analyze_message(text)
    assert result.risk_level == "Low Concern"
    assert result.risk_score < 25


def test_ambiguous_flash_sale_promotion():
    text = (
        "Weekend Flash Sale: 90% off clearance on select outdoor items today only! "
        "Check our seasonal catalog while supplies last."
    )
    result = analyze_message(text)
    # Triggers caution for unrealistic discount, but not high enough for Suspicious unless combined
    assert result.risk_level in ["Low Concern", "Needs Verification"]
    indicator_ids = [i.id for i in result.indicators]
    assert "MSG_SHOPPING_PROMOTION_BAIT" in indicator_ids


def test_ambiguous_coworker_urgent_meeting():
    text = (
        "Hey team, we have an urgent project sync in 10 minutes to review the Q3 slide deck before the board meeting."
    )
    result = analyze_message(text)
    # Simple operational urgency without threats or banking demands should remain Low Concern
    assert result.risk_level == "Low Concern"
    assert result.risk_score < 25
