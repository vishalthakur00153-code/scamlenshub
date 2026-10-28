import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional, Set

TARGETED_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "azure.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "facebook": ["facebook.com", "fb.com"],
    "whatsapp": ["whatsapp.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com", "github.io"],
    "internshala": ["internshala.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "sbi": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
}

SECURITY_CREDENTIAL_TERMS: Set[str] = {
    "login", "verify", "verification", "signin", "sign-in", "account",
    "security", "secure", "auth", "authenticate", "authentication",
    "banking", "update", "confirm", "confirmation", "password", "passcode",
    "wallet", "recovery", "unlock", "support", "helpdesk", "portal", "billing"
}

HIGH_ABUSE_TLDS: Set[str] = {
    "top", "buzz", "fit", "tk", "ml", "ga", "cf", "gq",
    "rest", "work", "icu", "cam", "monster", "click", "link",
    "country", "stream", "download", "racing"
}

KNOWN_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "buff.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl", "rotf.lol"
}

DANGEROUS_SCHEMES: Set[str] = {"javascript", "data", "file", "vbscript", "intent", "about"}

MULTI_PART_PUBLIC_SUFFIXES: Set[str] = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "ac.in",
    "edu.in", "res.in", "gov.in", "mil.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp",
    "com.br", "net.br", "org.br", "com.mx", "org.mx", "co.nz", "net.nz",
    "org.nz", "co.za", "org.za", "com.sg", "edu.sg", "gov.sg", "com.hk",
    "edu.hk", "gov.hk", "com.tw", "org.tw", "edu.tw", "gov.tw", "com.tr"
}


def is_ip_address(host: str) -> bool:
    """Checks whether the hostname is an IPv4 or IPv6 address."""
    h = host.strip()
    if h.startswith("[") and "]" in h:
        clean_host = h[1:h.index("]")]
    elif ":" in h and h.count(":") == 1:
        clean_host = h.split(":")[0]
    else:
        clean_host = h.strip("[]")

    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def parse_host_structure(raw_host: str) -> Dict[str, Any]:
    """
    Parses a hostname into its structural components:
    - is_ip: boolean flag
    - registrable_domain: the actual registered domain (e.g., example.com)
    - domain_name: the base domain name (e.g., example)
    - public_suffix: the TLD or ccTLD (e.g., com, co.uk)
    - subdomain: any labels preceding the registrable domain
    """
    h = raw_host.lower().strip(".")
    if h.startswith("[") and "]" in h:
        host = h[1:h.index("]")]
    elif ":" in h and h.count(":") == 1:
        host = h.split(":")[0]
    else:
        host = h.strip("[]")

    if not host:
        return {
            "is_ip": False,
            "registrable_domain": "",
            "domain_name": "",
            "public_suffix": "",
            "subdomain": "",
            "parts": [],
        }

    if is_ip_address(host):
        return {
            "is_ip": True,
            "registrable_domain": host,
            "domain_name": host,
            "public_suffix": "",
            "subdomain": "",
            "parts": [host],
        }

    parts = host.split(".")
    if len(parts) <= 1:
        return {
            "is_ip": False,
            "registrable_domain": host,
            "domain_name": host,
            "public_suffix": "",
            "subdomain": "",
            "parts": parts,
        }

    # Check for known 2-part public suffix (e.g. co.uk, com.au)
    candidate_2part = f"{parts[-2]}.{parts[-1]}"
    if candidate_2part in MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
        public_suffix = candidate_2part
        domain_name = parts[-3]
        registrable_domain = f"{domain_name}.{public_suffix}"
        subdomain = ".".join(parts[:-3])
    else:
        public_suffix = parts[-1]
        domain_name = parts[-2]
        registrable_domain = f"{domain_name}.{public_suffix}"
        subdomain = ".".join(parts[:-2])

    return {
        "is_ip": False,
        "registrable_domain": registrable_domain,
        "domain_name": domain_name,
        "public_suffix": public_suffix,
        "subdomain": subdomain,
        "parts": parts,
    }


def extract_word_tokens(text: str) -> Set[str]:
    """
    Splits text on hyphens, dots, underscores, and digits into distinct word tokens.
    Prevents false-positive substring matches (e.g. 'pineapple' won't match 'apple').
    """
    cleaned = text.lower()
    raw_tokens = re.split(r"[-._0-9/]+", cleaned)
    return {t for t in raw_tokens if len(t) >= 2}


def is_official_brand_domain(registrable_domain: str, brand: str) -> bool:
    """Verifies whether a registrable domain is in the known legitimate list for a brand."""
    legit_domains = TARGETED_BRANDS.get(brand, [])
    reg = registrable_domain.lower()
    return any(reg == legit or reg.endswith("." + legit) for legit in legit_domains)


def scan_url_rules(raw_url: str) -> List[Dict[str, Any]]:
    """
    Performs transparent, offline structural analysis of a URL.
    
    IMPORTANT ARCHITECTURAL NOTE:
    This engine operates strictly offline via syntactic and structural heuristics.
    It does NOT connect to live web servers, download content, or query external
    reputation blocklists or threat-intelligence feeds.
    """
    indicators: List[Dict[str, Any]] = []
    cleaned_url = raw_url.strip()

    # 1. Scheme Check
    parsed = urlparse(cleaned_url)
    scheme = parsed.scheme.lower()

    if scheme in DANGEROUS_SCHEMES:
        indicators.append({
            "id": "URL_DANGEROUS_SCHEME",
            "category": "Dangerous URI Scheme",
            "title": f"Dangerous Executable Scheme ('{scheme}:')",
            "severity": "high",
            "weight": 60,
            "description": f"The URL uses the '{scheme}:' scheme rather than a safe web protocol (https/http). This scheme is often used to execute scripts or access local files.",
            "action": "Do not open, execute, or paste this link into your address bar.",
            "matched_text": f"{scheme}:...",
        })
        return indicators

    # If scheme was omitted, prepend http:// to parse host and path
    if not scheme:
        parsed = urlparse(f"http://{cleaned_url}")
        scheme = "http"

    host = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # 2. Syntax & Host Presence Check
    if not host or " " in host or (":" in host and not is_ip_address(host)):
        indicators.append({
            "id": "URL_MALFORMED",
            "category": "Malformed URL Syntax",
            "title": "Invalid or Unparseable URL Structure",
            "severity": "caution",
            "weight": 25,
            "description": "The URL lacks a recognizable hostname or contains invalid characters. Malformed links are often generated by broken phishing scripts.",
            "action": "Double-check the link text. Ensure the complete address was copied without truncation.",
            "matched_text": cleaned_url[:60],
        })
        return indicators

    host_info = parse_host_structure(host)
    registrable_domain = host_info["registrable_domain"]
    subdomain = host_info["subdomain"]
    is_ip = host_info["is_ip"]
    tld = host_info["public_suffix"]

    # Tokenize host components for precise brand & credential matching
    host_tokens = extract_word_tokens(host)
    subdomain_tokens = extract_word_tokens(subdomain) if subdomain else set()
    path_tokens = extract_word_tokens(path + "/" + query)

    matched_auth_in_subdomain = subdomain_tokens.intersection(SECURITY_CREDENTIAL_TERMS)
    matched_auth_in_path = path_tokens.intersection(SECURITY_CREDENTIAL_TERMS)
    all_matched_auth = matched_auth_in_subdomain.union(matched_auth_in_path)

    # 3. Authority Obfuscation / Embedded Credentials Check
    if "@" in netloc or "@" in cleaned_url.split("?")[0].split("#")[0]:
        indicators.append({
            "id": "URL_EMBEDDED_CREDENTIALS",
            "category": "Authority Obfuscation",
            "title": "Misleading '@' Symbol in Web Address",
            "severity": "high",
            "weight": 45,
            "description": f"The URL contains an '@' character in the domain authority. Browsers connect only to the host after the '@', ignoring everything before it. This deceptive pattern is used to disguise the real destination.",
            "action": f"Do not click. Note that the browser will connect to '{host}', NOT the text before the '@' symbol.",
            "matched_text": netloc,
        })

    # 4. Host Structure Check: Raw IP Address Host
    if is_ip:
        indicators.append({
            "id": "URL_RAW_IP_HOST",
            "category": "Host Structure",
            "title": "Raw IP Address Used as Hostname",
            "severity": "high",
            "weight": 40,
            "description": f"The link points to a numerical IP address ('{host}') rather than a registered domain name. Legitimate consumer services and financial platforms almost never use naked IP addresses for public access.",
            "action": "Avoid entering credentials or downloading files from links using raw numerical IP addresses.",
            "matched_text": host,
        })

        if all_matched_auth:
            auth_terms = ", ".join(sorted(all_matched_auth))
            indicators.append({
                "id": "URL_IP_HOST_WITH_CREDENTIAL_LURE",
                "category": "Credential Lure on Raw IP",
                "title": f"Authentication / Login Lure on Raw IP ({auth_terms})",
                "severity": "high",
                "weight": 30,
                "description": f"The URL hosts authentication/security paths ({auth_terms}) on a raw numeric IP address ('{host}'). Legitimate financial and identity providers never conduct authentication over naked IP hosts.",
                "action": "Do not enter login credentials, passwords, or personal details on raw IP web pages.",
                "matched_text": f"{host}{path}",
            })

    # 5. Homograph / Punycode Deception Check
    if host.startswith("xn--") or ".xn--" in host:
        indicators.append({
            "id": "URL_PUNYCODE_HOMOGRAPH",
            "category": "Homograph Deception",
            "title": "Punycode Encoded Domain (Potential Visual Lookalike)",
            "severity": "high",
            "weight": 40,
            "description": f"The domain uses Punycode encoding ('{host}'). Internationalized domain names can display characters from Greek or Cyrillic alphabets that look identical to Latin letters to visually mimic reputable websites.",
            "action": "Examine the decoded domain structure carefully before entering sensitive data.",
            "matched_text": host,
        })

    # 6. URL Shortener Masking Check
    if host in KNOWN_SHORTENERS or any(host.endswith("." + s) for s in KNOWN_SHORTENERS):
        indicators.append({
            "id": "URL_SHORTENER_OBFUSCATION",
            "category": "Destination Masking",
            "title": "URL Shortener Masks Destination",
            "severity": "caution",
            "weight": 25,
            "description": f"The link uses a URL shortening service ('{host}'). While shortening is common in marketing, it conceals the true destination host and prevents prior structural inspection.",
            "action": "Expand or preview the shortened link before opening it (e.g. using a preview tool or adding '+' at the end of some shortlinks).",
            "matched_text": host,
        })

    # 7. Brand Impersonation & Deceptive Subdomain Analysis
    # A brand is flagged ONLY if:
    #   1. A known brand token is present in the host labels, AND
    #   2. The registrable domain is NOT an official domain for that brand.
    for brand, legit_domains in TARGETED_BRANDS.items():
        if brand in host_tokens:
            is_official = is_official_brand_domain(registrable_domain, brand)
            if not is_official:
                # Primary Brand Mismatch Indicator
                indicators.append({
                    "id": f"URL_BRAND_IN_UNRELATED_DOMAIN",
                    "category": "Brand Impersonation Risk",
                    "title": f"Brand Keyword '{brand}' in Unrelated Domain",
                    "severity": "high",
                    "weight": 35,
                    "description": (
                        f"The link references the brand '{brand}' in its hostname, but the actual registrable domain "
                        f"is '{registrable_domain}', not an official domain ({', '.join(legit_domains)}). "
                        f"Words in a subdomain or host prefix do not prove ownership by the named brand."
                    ),
                    "action": f"Do not enter credentials. Visit {legit_domains[0]} directly by typing it in your browser address bar.",
                    "matched_text": host,
                })

                # Deceptive Compound Indicator: Brand + Credential Terms in Unrelated Domain
                if all_matched_auth:
                    combined_terms = ", ".join(sorted(all_matched_auth))
                    indicators.append({
                        "id": "URL_DECEPTIVE_BRAND_CREDENTIAL_COMBO",
                        "category": "Credential Harvesting Pattern",
                        "title": f"Deceptive Brand ('{brand}') + Authentication Lure Combination",
                        "severity": "high",
                        "weight": 40,
                        "description": (
                            f"The URL combines a targeted brand ('{brand}') with sensitive authentication/verification "
                            f"terms ({combined_terms}) under an unrelated domain ('{registrable_domain}'). "
                            f"This compound pattern strongly correlates with credential harvesting and phishing pages."
                        ),
                        "action": "Do not enter passwords, OTPs, or financial details on this page.",
                        "matched_text": f"{brand} + {combined_terms}",
                    })
                break

    # 8. Subdomain Security Lure (Without Brand Match)
    # If a subdomain stacks security/login terms on an unofficial domain
    if matched_auth_in_subdomain and not any(i["id"] == "URL_DECEPTIVE_BRAND_CREDENTIAL_COMBO" for i in indicators):
        lure_terms = ", ".join(sorted(matched_auth_in_subdomain))
        indicators.append({
            "id": "URL_SUBDOMAIN_SECURITY_LURE",
            "category": "Domain Structure Deception",
            "title": f"Security / Login Lure Terms in Subdomain ({lure_terms})",
            "severity": "warning",
            "weight": 25,
            "description": (
                f"The subdomain contains authentication terms ({lure_terms}) targeting the registered domain "
                f"'{registrable_domain}'. Attackers use deceptive subdomains to mislead users viewing small mobile screens."
            ),
            "action": f"Check the registrable domain ('{registrable_domain}') to verify if you have an existing relationship with this provider.",
            "matched_text": subdomain,
        })

    # 9. Insecure HTTP on Sensitive / Credential Themed Links
    if scheme == "http" and all_matched_auth:
        indicators.append({
            "id": "URL_INSECURE_HTTP_ON_AUTH",
            "category": "Insecure Transport",
            "title": "Unencrypted HTTP on Credential-Themed Address",
            "severity": "warning",
            "weight": 20,
            "description": (
                "The link uses unencrypted HTTP ('http://') rather than HTTPS, while referencing authentication "
                "or security keywords. Legitimate financial and account portals strictly require encrypted HTTPS connections."
            ),
            "action": "Never enter passwords or confidential details on an unencrypted HTTP link.",
            "matched_text": f"http://{host}",
        })

    # 10. Excessive Subdomain Nesting
    subdomain_parts = subdomain.split(".") if subdomain else []
    if len(subdomain_parts) >= 3 and not is_ip:
        indicators.append({
            "id": "URL_EXCESSIVE_SUBDOMAINS",
            "category": "Domain Obfuscation",
            "title": "Excessive Subdomain Levels",
            "severity": "caution",
            "weight": 20,
            "description": (
                f"The domain contains {len(subdomain_parts)} subdomain levels ('{subdomain}'). "
                f"Nesting multiple subdomains is commonly used to push the real registered domain "
                f"('{registrable_domain}') out of view in narrow browser address bars."
            ),
            "action": f"Verify that the entity controlling '{registrable_domain}' is the one you intend to visit.",
            "matched_text": host,
        })

    # 11. High-Abuse Top-Level Domain (TLD)
    if tld in HIGH_ABUSE_TLDS:
        indicators.append({
            "id": "URL_HIGH_ABUSE_TLD",
            "category": "High-Risk Domain Extension",
            "title": f"Elevated-Abuse Domain Extension (.{tld})",
            "severity": "caution",
            "weight": 15,
            "description": (
                f"The domain uses the '.{tld}' extension, which historically exhibits elevated abuse rates in "
                f"disposable phishing kits. Having this extension does not prove malicious intent, but warrants heightened verification."
            ),
            "action": "Exercise added caution and independently verify the organization.",
            "matched_text": f".{tld}",
        })

    # 12. Non-Standard Port Check
    if parsed.port and parsed.port not in (80, 443, 8000, 8080):
        indicators.append({
            "id": "URL_UNUSUAL_PORT",
            "category": "Non-Standard Port",
            "title": f"Unusual Network Port (:{parsed.port})",
            "severity": "caution",
            "weight": 15,
            "description": f"The URL connects on a non-standard web port (:{parsed.port}). Legitimate public web applications standardly operate on ports 80 (HTTP) or 443 (HTTPS).",
            "action": "Ensure this network port is expected before accessing the link.",
            "matched_text": f":{parsed.port}",
        })

    return indicators
