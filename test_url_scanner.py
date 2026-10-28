import pytest
from app.engine import analyze_url


def test_paypal_login_verify_subdomain_spoof():
    """
    Tests that http://paypal-login-verify.example.com is correctly flagged
    as Suspicious due to brand-impersonation and credential lure in the subdomain,
    and is NOT classified as Low Concern.
    """
    url = "http://paypal-login-verify.example.com"
    result = analyze_url(url)

    # Must NOT be Low Concern
    assert result.risk_level != "Low Concern"
    assert result.risk_level == "Suspicious"
    assert result.risk_score >= 60

    indicator_ids = [i.id for i in result.indicators]
    # Brand mismatch in unrelated domain must be detected
    assert "URL_BRAND_IN_UNRELATED_DOMAIN" in indicator_ids
    # Deceptive brand + credential combo must be detected
    assert "URL_DECEPTIVE_BRAND_CREDENTIAL_COMBO" in indicator_ids
    # Insecure HTTP on credential-themed link
    assert "URL_INSECURE_HTTP_ON_AUTH" in indicator_ids

    # Transparent explanation should mention the actual registered domain (example.com)
    brand_ind = next(i for i in result.indicators if i.id == "URL_BRAND_IN_UNRELATED_DOMAIN")
    assert "example.com" in brand_ind.description
    assert "paypal" in brand_ind.description


def test_legitimate_paypal_official_domain():
    """
    Tests that official PayPal URLs (with or without www, with or without signin path)
    are classified as Low Concern and not flagged for brand impersonation or login keywords.
    """
    urls = [
        "https://www.paypal.com/",
        "https://paypal.com/",
        "https://www.paypal.com/signin",
        "https://www.paypal.com/us/home",
    ]
    for u in urls:
        result = analyze_url(u)
        assert result.risk_level == "Low Concern", f"Failed for {u}: got {result.risk_level}"
        assert result.risk_score < 25
        assert len(result.indicators) == 0


def test_legitimate_github_official_domain():
    """
    Tests that https://github.com/ and https://github.com/login are Low Concern.
    """
    urls = [
        "https://github.com/",
        "https://github.com/login",
        "https://github.com/fastapi/fastapi",
    ]
    for u in urls:
        result = analyze_url(u)
        assert result.risk_level == "Low Concern", f"Failed for {u}: got {result.risk_level}"
        assert result.risk_score < 25
        assert len(result.indicators) == 0


def test_legitimate_example_domain():
    """
    Tests that https://example.com/ is classified as Low Concern with zero indicators.
    """
    url = "https://example.com/"
    result = analyze_url(url)
    assert result.risk_level == "Low Concern"
    assert result.risk_score == 0
    assert len(result.indicators) == 0


def test_invalid_urls_and_malformed_input():
    """
    Tests malformed URLs, empty hosts, and invalid syntax.
    """
    # Missing host / malformed
    result_malformed = analyze_url("http://")
    assert result_malformed.risk_level in ["Needs Verification", "Suspicious"]
    assert any(i.id == "URL_MALFORMED" for i in result_malformed.indicators)

    # Executable / dangerous scheme
    result_scheme = analyze_url("javascript:alert(document.cookie)")
    assert result_scheme.risk_level == "Suspicious"
    assert any(i.id == "URL_DANGEROUS_SCHEME" for i in result_scheme.indicators)

    # Space in host
    result_spaces = analyze_url("http://invalid host name.com")
    assert any(i.id == "URL_MALFORMED" for i in result_spaces.indicators)


def test_no_false_positive_on_word_subsets():
    """
    Tests that domains containing brand words as substrings (e.g. pineapple.com)
    are NOT falsely flagged as brand mismatches for Apple.
    """
    urls = [
        "https://pineapple.com",
        "https://applegate.com",
    ]
    for u in urls:
        result = analyze_url(u)
        assert result.risk_level == "Low Concern"
        assert not any("URL_BRAND" in i.id for i in result.indicators)


def test_suspicious_raw_ip_address_host():
    url = "http://192.168.1.100:8080/secure/bank-login"
    result = analyze_url(url)
    assert result.risk_level == "Suspicious"
    indicator_ids = [i.id for i in result.indicators]
    assert "URL_RAW_IP_HOST" in indicator_ids


def test_suspicious_raw_ipv6_address_host():
    url = "http://[2001:db8::1]:8080/secure/bank-login"
    result = analyze_url(url)
    assert result.risk_level == "Suspicious"
    indicator_ids = [i.id for i in result.indicators]
    assert "URL_RAW_IP_HOST" in indicator_ids
    assert "URL_IP_HOST_WITH_CREDENTIAL_LURE" in indicator_ids


def test_suspicious_punycode_lookalike():
    url = "https://xn--pple-43d.com/support/login"
    result = analyze_url(url)
    assert result.risk_level in ["Needs Verification", "Suspicious"]
    indicator_ids = [i.id for i in result.indicators]
    assert "URL_PUNYCODE_HOMOGRAPH" in indicator_ids


def test_suspicious_embedded_credentials():
    url = "http://legitimate-bank.com@evil-phishing-host.com/login"
    result = analyze_url(url)
    assert result.risk_level in ["Needs Verification", "Suspicious"]
    indicator_ids = [i.id for i in result.indicators]
    assert "URL_EMBEDDED_CREDENTIALS" in indicator_ids


def test_ambiguous_url_shortener():
    url = "https://bit.ly/3xSampleLink"
    result = analyze_url(url)
    assert result.risk_level in ["Low Concern", "Needs Verification"]
    indicator_ids = [i.id for i in result.indicators]
    assert "URL_SHORTENER_OBFUSCATION" in indicator_ids


def test_ambiguous_excessive_subdomains():
    url = "https://a.b.c.d.internal-wiki.com/welcome"
    result = analyze_url(url)
    assert result.risk_level in ["Low Concern", "Needs Verification"]
    indicator_ids = [i.id for i in result.indicators]
    assert "URL_EXCESSIVE_SUBDOMAINS" in indicator_ids


def test_url_limitations_explicit_notice():
    """
    Verifies that URL analysis outputs explicit limitations distinguishing
    heuristic syntax analysis from live threat intelligence feeds.
    """
    result = analyze_url("https://example.com/")
    lim_text = " ".join(result.limitations)
    assert "Static URL-Pattern Analysis" in lim_text
    assert "No Live Threat Intelligence" in lim_text
