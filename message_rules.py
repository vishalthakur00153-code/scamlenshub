import re
from typing import List, Dict, Any, Tuple


MESSAGE_RULES: List[Dict[str, Any]] = [
    {
        "id": "MSG_UPFRONT_FEE",
        "category": "Upfront Payment Request",
        "title": "Demand for Upfront Fee or Deposit",
        "severity": "high",
        "weight": 35,
        "patterns": [
            r"\b(?:pay|send|transfer|deposit)\s+(?:a\s+)?(?:refundable\s+)?(?:security|registration|training|application|processing|onboarding|equipment|laptop|verification)\s+fee\b",
            r"\b(?:registration|security|training|application|processing|laptop|equipment)\s+(?:fee|deposit)\s+(?:of|is|required)\b",
            r"\bpay\s+(?:rs\.?|inr|\$|usd|eur|£)\s*[0-9,]+\s+(?:as|for|towards)\s+(?:a\s+)?(?:fee|deposit|training|kit|laptop|onboarding)\b",
            r"\bfee\s+will\s+be\s+refunded\s+(?:after|with|in)\s+(?:first|1st)\s+(?:salary|month|stipend)\b",
            r"\bpay\s+(?:before|prior\s+to)\s+(?:joining|receiving|interview|offer\s+letter|start)\b",
        ],
        "description": "The message requests money before an internship, job, or reward is delivered. Legitimate employers virtually never charge candidates for equipment, registration, or onboarding.",
        "action": "Do not send any funds. Real companies provide equipment and onboarding without upfront candidate charges.",
    },
    {
        "id": "MSG_CREDENTIAL_OTP",
        "category": "Credential & OTP Harvesting",
        "title": "Request for OTP, PIN, or Sensitive Credentials",
        "severity": "high",
        "weight": 40,
        "patterns": [
            r"\b(?:share|send|provide|give|enter|forward)\s+(?:your\s+)?(?:6-digit\s+|one-time\s+)?(?:otp|pin|cvv|password|passcode|mpin)\b",
            r"\botp\s+(?:sent\s+to\s+your\s+mobile|verification\s+code|received\s+on\s+phone)\b",
            r"\bverify\s+(?:your\s+)?(?:bank\s+account|card|credentials|password)\s+by\s+(?:replying|sending)\b",
            r"\bdo\s+not\s+share\s+this\s+otp\s+with\s+anyone\s+except\b",
        ],
        "description": "The message asks for an OTP, password, PIN, or banking credentials. Financial institutions and genuine support teams never request your verification code or secret PIN.",
        "action": "Never share OTPs, PINs, or passwords with anyone over text, email, or telephone.",
    },
    {
        "id": "MSG_LOTTERY_PRIZE",
        "category": "Unexpected Prize / Lottery",
        "title": "Unexpected Lottery Win or Unsolicited Prize Claim",
        "severity": "high",
        "weight": 35,
        "patterns": [
            r"\b(?:congratulations|congrats|winner|selected)\b.{0,60}\b(?:won|awarded|chosen\s+for)\b.{0,40}(?:prize|lottery|jackpot|cash\s+reward|sweepstake|\$|rs\.?|inr|crore|lakh)",
            r"\b(?:lucky\s+draw|mega\s+jackpot|international\s+lottery|kbc\s+lottery)\b",
            r"\bclaim\s+(?:your\s+)?(?:prize|reward|winnings|jackpot)\s+(?:by|within|now|today)\b",
            r"\byou\s+have\s+been\s+selected\s+as\s+the\s+(?:lucky\s+)?winner\b",
        ],
        "description": "Claims you have won a lottery, sweepstakes, or high-value prize you did not deliberately enter. Scammers use this bait to ask for processing fees or banking credentials.",
        "action": "Remember: You cannot win a legitimate lottery or contest that you never entered. Disregard the claim.",
    },
    {
        "id": "MSG_URGENT_COERCION",
        "category": "Artificial Urgency & Coercion",
        "title": "High Urgency, Deadline Pressure, or Threat of Suspension",
        "severity": "warning",
        "weight": 25,
        "patterns": [
            r"\b(?:immediately|urgently|within\s+(?:24|12|2|1)\s+hours?|before\s+it(?:'s|\s+is)\s+too\s+late)\b.{0,60}\b(?:blocked|suspended|cancelled|terminated|disconnected|frozen|closed)\b",
            r"\b(?:account|card|sim|service|electricity|power|kyc)\b.{0,40}\b(?:will\s+be|has\s+been)\s+(?:\w+\s+)?(?:suspended|blocked|deactivated|disconnected|frozen|closed)\b",
            r"\b(?:prevent|avoid)\s+(?:permanent\s+)?(?:deactivation|suspension|closure|blocking|disconnection)\b",
            r"\bact\s+now\s+or\s+(?:legal|police|arrest|court)\s+(?:action|notice|warrant)\b",
            r"\bfinal\s+(?:warning|notice|reminder)\s+(?:before|to\s+avoid)\b",
            r"\burgent\s+action\s+required\b",
        ],
        "description": "Manufactures panic using artificial deadlines or threats of service disconnection/legal action. Urgency is designed to prevent you from calmly verifying the claim.",
        "action": "Pause and breathe. Contact the official institution directly through their verified website or public phone number, not the contact details in the message.",
    },
    {
        "id": "MSG_OFF_PLATFORM",
        "category": "Suspicious Off-Platform Redirection",
        "title": "Redirection to Telegram or WhatsApp for Official Matters",
        "severity": "caution",
        "weight": 20,
        "patterns": [
            r"\b(?:contact|connect|reach|message|dm)\s+(?:\w+\s+){0,4}(?:on|via|through)?\s*(?:telegram|whatsapp)\b",
            r"\btelegram\s*(?::|at)?\s*@\w+\b",
            r"\b(?:t\.me|wa\.me|api\.whatsapp\.com)/\S+\b",
            r"\binterview\s+(?:conducted|held|scheduled)\s+(?:solely\s+)?(?:on|via)\s+(?:telegram|whatsapp)\b",
        ],
        "description": "Directs communication to encrypted chat apps (like Telegram or WhatsApp) rather than official corporate emails or portals. This hides the sender's identity and evades platform safeguards.",
        "action": "Insist on verified corporate communication (e.g., an @company.com official domain email) before sharing personal resumes or documents.",
    },
    {
        "id": "MSG_UNREALISTIC_EARNINGS",
        "category": "Unrealistic Job / High Pay",
        "title": "Unrealistic Compensation for Minimal Work (Task Scam)",
        "severity": "warning",
        "weight": 25,
        "patterns": [
            r"\bearn\s+(?:rs\.?|inr|\$|usd|eur|£)\s*[0-9,]+\s+(?:daily|per\s+day|an\s+hour|hourly)\s+(?:from\s+home|by\s+liking|just\s+watching)\b",
            r"\b(?:part-time|work\s+from\s+home|wfh)\s+job.{0,40}(?:10-15\s+mins|1-2\s+hours|no\s+experience).{0,40}(?:earn|daily\s+income)\b",
            r"\b(?:like\s+youtube\s+videos|rate\s+hotels|complete\s+simple\s+tasks|review\s+products)\s+and\s+earn\b",
            r"\bguaranteed\s+(?:daily|monthly)\s+(?:income|payout|returns|stipend)\b",
        ],
        "description": "Promises high daily payouts for trivial tasks like reviewing hotels or liking videos. This is characteristic of task scams, where victims are lured with small payments then asked to deposit larger sums.",
        "action": "Be skeptical of 'easy money' offers. Legitimate companies do not pay hundreds of dollars for trivial video clicks or rating tasks.",
    },
    {
        "id": "MSG_IMPERSONATION_AUTHORITY",
        "category": "Authority Impersonation",
        "title": "Impersonation of Police, Customs, Tax, or Delivery Services",
        "severity": "high",
        "weight": 35,
        "patterns": [
            r"\b(?:customs|parcel|courier|fedex|dhl)\s+(?:department|officer|clearance|alert)\b.{0,60}\b(?:drugs|illegal|contraband|penalty|duty|held)\b",
            r"\b(?:arrest\s+warrant|cbi|fbi|police\s+complaint|cyber\s+crime\s+cell|narcotics\s+control)\b",
            r"\b(?:tax\s+refund|irs\s+refund|income\s+tax\s+department)\b.{0,40}\b(?:claim|pending|urgent\s+penalty)\b",
            r"\byour\s+package\s+(?:cannot\s+be\s+delivered|is\s+held)\s+due\s+to\s+(?:unpaid|customs|address\s+fee)\b",
        ],
        "description": "Falsely invokes law enforcement, customs officials, or courier dispatchers to scare you into making an emergency payment.",
        "action": "Government agencies and reputable courier services do not settle legal issues or parcel detentions via instant personal bank transfers.",
    },
    {
        "id": "MSG_SUSPICIOUS_PAYMENT_METHOD",
        "category": "Untraceable Payment Demands",
        "title": "Request for Payment via Gift Cards or Cryptocurrency",
        "severity": "high",
        "weight": 35,
        "patterns": [
            r"\b(?:pay|send|transfer|deposit)\s+(?:via|using|through|with)?\s*(?:crypto|bitcoin|usdt|btc|ethereum|crypto\s+wallet)\b",
            r"\b(?:pay|send|transfer)\s+(?:via|using|through|with)\s+(?:gift\s+cards?|itunes\s+cards?|google\s+play\s+cards?|apple\s+gift\s+card|steam\s+card)\b",
            r"\b(?:crypto|bitcoin|usdt|btc|ethereum)\s+wallet\b",
            r"\bdeposit\s+cash\s+into\s+(?:atm|kiosk|personal\s+account)\b",
        ],
        "description": "Demands payment via untraceable and irreversible payment methods like gift cards or cryptocurrency wallets.",
        "action": "Never pay any official fees, fines, or purchases using gift cards or anonymous crypto wallets. These transactions are irreversible.",
    },
    {
        "id": "MSG_SHOPPING_PROMOTION_BAIT",
        "category": "Misleading Shopping Promotion",
        "title": "Unrealistic Discount or Flash Deal Bait",
        "severity": "caution",
        "weight": 15,
        "patterns": [
            r"\b(?:9[0-9]%|8[5-9]%)\s+(?:off|discount|sale)\s+(?:today\s+only|on\s+all\s+items|clearance)\b",
            r"\b(?:iphone|samsung\s+galaxy|macbook|ps5)\s+for\s+(?:just|only)\s+(?:rs\.?|inr|\$|usd)\s*[0-9]{1,3}\b",
            r"\bfree\s+(?:gift|giveaway|sample|trial)\s+just\s+pay\s+(?:shipping|courier|delivery)\b",
            r"\bexclusive\s+(?:deal|clearance)\s+for\s+first\s+[0-9]+\s+(?:callers|orders|customers)\b",
        ],
        "description": "Promotes deep discounts (e.g. 90% off luxury goods) or expensive electronics for nominal fees. Such deals often lead to fake storefronts that steal credit card details.",
        "action": "Check the official manufacturer or established retailer website to verify whether any such campaign exists.",
    },
]


def extract_matched_context(text: str, match_span: Tuple[int, int], window: int = 40) -> str:
    """Extract a small snippet of text around the regex match for transparent user feedback."""
    start = max(0, match_span[0] - window)
    end = min(len(text), match_span[1] + window)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end].strip()}{suffix}"


def scan_message_rules(text: str) -> List[Dict[str, Any]]:
    """
    Evaluates message text against transparent, rule-based detection patterns.
    Returns detected indicators with severity, matched snippets, and educational guidance.
    """
    detected_indicators: List[Dict[str, Any]] = []

    for rule in MESSAGE_RULES:
        for pattern in rule["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_snippet = extract_matched_context(text, match.span())
                detected_indicators.append({
                    "id": rule["id"],
                    "category": rule["category"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "weight": rule["weight"],
                    "description": rule["description"],
                    "action": rule["action"],
                    "matched_text": matched_snippet,
                })
                break

    return detected_indicators
