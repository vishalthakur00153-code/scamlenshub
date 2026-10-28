from datetime import datetime, timezone
from typing import List, Dict, Any
from app.models import ScanResult, Indicator
from app.rules.message_rules import scan_message_rules
from app.rules.url_rules import scan_url_rules

# Documented Risk Scoring Thresholds:
# -----------------------------------------------------------
# Score 0 to 24  : "Low Concern"
#                  No significant heuristic threat indicators identified. Standard vigilance applies.
# Score 25 to 59 : "Needs Verification"
#                  Moderate or cautionary indicators present (e.g., URL shortener, non-standard TLD,
#                  unencrypted transport, or standalone urgency). Independent verification recommended.
# Score 60 to 100: "Suspicious"
#                  High-risk compound patterns identified (e.g., brand-impersonation + login terms,
#                  upfront fee demands, OTP harvesting, raw IP hosting, or dangerous URI schemes).
# -----------------------------------------------------------

MESSAGE_LIMITATIONS: List[str] = [
    "Rule-based detection identifies heuristic risk patterns; it does not constitute definitive proof of fraud or legitimacy.",
    "Legitimate entities may occasionally use urgent phrasing, and novel scams can mimic genuine correspondence.",
    "This tool performs static structural analysis without accessing external private databases or launching active network probes.",
    "Always independently verify suspicious claims directly through official websites or known public phone numbers.",
]

URL_LIMITATIONS: List[str] = [
    "Static URL-Pattern Analysis Only: Evaluates syntax, domain structures, and naming heuristics offline without visiting the remote server.",
    "No Live Threat Intelligence Integration: This tool does NOT query external blocklists (e.g. Google Safe Browsing, VirusTotal, PhishTank), WHOIS domain age records, or live DNS status.",
    "Heuristic Evidence, Not Definitive Proof: Structural anomalies indicate risk, but cannot definitively prove whether a website is malicious or safe.",
    "Always check the browser address bar directly and verify SSL/TLS digital certificates before entering sensitive credentials.",
]


def calculate_risk_level(score: int) -> str:
    """Categorizes composite risk score into one of three documented, transparent tiers."""
    if score >= 60:
        return "Suspicious"
    elif score >= 25:
        return "Needs Verification"
    else:
        return "Low Concern"


def generate_summary(input_type: str, risk_level: str, indicators: List[Dict[str, Any]]) -> str:
    """Generates an objective, transparent, and non-definitive summary for the user."""
    count = len(indicators)
    if risk_level == "Suspicious":
        high_severity_count = sum(1 for i in indicators if i.get("severity") == "high")
        return (
            f"Caution advised: ScamLens identified {count} warning indicator{'s' if count != 1 else ''} "
            f"(including {high_severity_count} high-severity pattern{'s' if high_severity_count != 1 else ''}). "
            f"The analyzed {input_type} exhibits patterns frequently observed in social engineering or brand-spoofing campaigns. "
            f"Treat these indicators as evidence warranting extreme caution, not definitive proof of fraud."
        )
    elif risk_level == "Needs Verification":
        return (
            f"ScamLens flagged {count} cautionary pattern{'s' if count != 1 else ''} in this {input_type}. "
            f"While these indicators represent structural anomalies rather than definitive proof of malice, "
            f"independent verification through official channels is strongly advised before entering credentials or taking action."
        )
    else:
        return (
            f"No prominent threat patterns or known scam triggers were identified in this {input_type}. "
            f"However, rule-based screening cannot guarantee safety. Continue exercising standard digital vigilance."
        )


def build_recommended_actions(indicators: List[Dict[str, Any]], input_type: str, risk_level: str) -> List[str]:
    """Compiles a de-duplicated, prioritized checklist of practical safety recommendations."""
    actions: List[str] = []

    for ind in indicators:
        act = ind.get("action")
        if act and act not in actions:
            actions.append(act)

    if risk_level == "Suspicious":
        if "Never enter passwords, OTPs, or financial details on unverified pages." not in actions:
            actions.append("Never enter passwords, OTPs, or financial details on unverified pages.")
        if "Look up the official organization directly via a reputable search engine." not in actions:
            actions.append("Look up the official organization directly via a reputable search engine.")
    elif risk_level == "Needs Verification":
        if "Verify the registered domain name directly in your browser address bar before interacting." not in actions:
            actions.append("Verify the registered domain name directly in your browser address bar before interacting.")
        if "Avoid clicking links directly from unsolicited SMS or direct messages." not in actions:
            actions.append("Avoid clicking links directly from unsolicited SMS or direct messages.")
    else:
        actions.append("Maintain good digital hygiene: verify unexpected requests through established channels.")
        actions.append("Keep your device browser and security tools updated.")

    return actions[:5]


def analyze_message(text: str) -> ScanResult:
    """
    Analyzes message text against transparent rules.
    Stateless: Text is analyzed in-memory and never persisted.
    """
    raw_indicators = scan_message_rules(text)

    total_score = min(100, sum(ind.get("weight", 15) for ind in raw_indicators))
    risk_level = calculate_risk_level(total_score)

    summary = generate_summary("message", risk_level, raw_indicators)
    actions = build_recommended_actions(raw_indicators, "message", risk_level)

    cleaned = text.strip()
    preview = cleaned[:140] + ("..." if len(cleaned) > 140 else "")

    pydantic_indicators = [
        Indicator(
            id=i["id"],
            category=i["category"],
            title=i["title"],
            description=i["description"],
            severity=i["severity"],
            matched_text=i.get("matched_text"),
        )
        for i in raw_indicators
    ]

    return ScanResult(
        input_type="message",
        analyzed_preview=preview,
        risk_level=risk_level,
        risk_score=total_score,
        summary=summary,
        indicators=pydantic_indicators,
        recommended_actions=actions,
        limitations=MESSAGE_LIMITATIONS,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        is_definitive_claim=False,
    )


def analyze_url(url: str) -> ScanResult:
    """
    Analyzes URL structurally against offline syntax and structural rules.
    Stateless: Never opens the link, never queries remote databases, never stores the URL.
    """
    raw_indicators = scan_url_rules(url)

    total_score = min(100, sum(ind.get("weight", 15) for ind in raw_indicators))
    risk_level = calculate_risk_level(total_score)

    summary = generate_summary("URL", risk_level, raw_indicators)
    actions = build_recommended_actions(raw_indicators, "URL", risk_level)

    cleaned = url.strip()
    preview = cleaned[:140] + ("..." if len(cleaned) > 140 else "")

    pydantic_indicators = [
        Indicator(
            id=i["id"],
            category=i["category"],
            title=i["title"],
            description=i["description"],
            severity=i["severity"],
            matched_text=i.get("matched_text"),
        )
        for i in raw_indicators
    ]

    return ScanResult(
        input_type="url",
        analyzed_preview=preview,
        risk_level=risk_level,
        risk_score=total_score,
        summary=summary,
        indicators=pydantic_indicators,
        recommended_actions=actions,
        limitations=URL_LIMITATIONS,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        is_definitive_claim=False,
    )
