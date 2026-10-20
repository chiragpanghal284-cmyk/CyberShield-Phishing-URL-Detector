"""
CyberShield – Phishing URL Detection Engine
Applies heuristic rules to estimate phishing risk.
WARNING: Heuristic results are NOT definitive phishing detection.
"""

import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Individual rule functions
# Each returns (triggered: bool, reason: str, weight: int)
# ---------------------------------------------------------------------------

def check_ip_hostname(parsed) -> tuple:
    """Flag URLs that use an IP address instead of a domain name."""
    hostname = parsed.hostname or ""
    ipv4 = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)
    if ipv4:
        return True, "Hostname is an IP address (e.g. 192.168.1.1) – legitimate sites rarely use this.", 3
    return False, "", 0


def check_url_length(parsed) -> tuple:
    """Very long URLs are a common phishing tactic."""
    url_str = parsed.geturl()
    if len(url_str) > 100:
        return True, f"URL is unusually long ({len(url_str)} chars) – attackers pad URLs to hide the real destination.", 2
    return False, "", 0


def check_at_symbol(parsed) -> tuple:
    """An @ in the URL causes browsers to ignore everything before it."""
    if "@" in (parsed.netloc or ""):
        return True, "URL contains '@' in the host part – browsers ignore everything before '@', a classic phishing trick.", 3
    return False, "", 0


def check_multiple_subdomains(parsed) -> tuple:
    """Excessive subdomains mimic trusted brands (e.g. paypal.secure.evil.com)."""
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) > 4:
        return True, f"URL has {len(parts)} subdomain levels – phishing pages often stack subdomains to look trustworthy.", 2
    return False, "", 0


def check_suspicious_keywords(parsed) -> tuple:
    """Common phishing keywords in the URL path or query."""
    keywords = [
        "login", "verify", "update", "secure", "account",
        "banking", "confirm", "password", "credential", "signin",
        "paypal", "ebay", "amazon", "microsoft", "apple",
    ]
    url_lower = parsed.geturl().lower()
    found = [kw for kw in keywords if kw in url_lower]
    if found:
        return True, f"URL contains suspicious keyword(s): {', '.join(found)}.", 1
    return False, "", 0


def check_https(parsed) -> tuple:
    """HTTP (not HTTPS) means no transport encryption – a weak signal on its own."""
    if parsed.scheme == "http":
        return True, "URL uses HTTP instead of HTTPS – data is transmitted unencrypted.", 1
    return False, "", 0


def check_hyphen_in_domain(parsed) -> tuple:
    """Hyphens in the domain are often used to spoof brand names (e.g. pay-pal.com)."""
    hostname = parsed.hostname or ""
    # Only check the registered domain (last two parts), not TLD
    parts = hostname.split(".")
    domain_part = parts[-2] if len(parts) >= 2 else hostname
    if "-" in domain_part:
        return True, f"Domain '{domain_part}' contains a hyphen – often used to mimic trusted brand names.", 1
    return False, "", 0


def check_double_slash_redirect(parsed) -> tuple:
    """Double slashes in the path signal a redirect attempt."""
    path = parsed.path or ""
    if "//" in path:
        return True, "URL path contains '//' – this may indicate a redirect to a different site.", 2
    return False, "", 0


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

RULES = [
    check_ip_hostname,
    check_url_length,
    check_at_symbol,
    check_multiple_subdomains,
    check_suspicious_keywords,
    check_https,
    check_hyphen_in_domain,
    check_double_slash_redirect,
]


def analyze_url(url: str) -> dict:
    """
    Analyze a URL and return a risk report.

    Returns a dict with:
        valid        – bool, whether the URL could be parsed
        score        – int, cumulative risk weight (0+)
        category     – str, 'Low' | 'Medium' | 'High'
        reasons      – list[str], human-readable explanations
        url          – str, the original URL
    """
    url = url.strip()

    # Basic format validation
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {"valid": False, "url": url, "score": 0,
                    "category": "Invalid", "reasons": ["URL is not valid – make sure it starts with http:// or https://"]}
    except Exception:
        return {"valid": False, "url": url, "score": 0,
                "category": "Invalid", "reasons": ["URL could not be parsed."]}

    triggered_reasons = []
    total_score = 0

    for rule in RULES:
        flagged, reason, weight = rule(parsed)
        if flagged:
            triggered_reasons.append(reason)
            total_score += weight

    # Map score to category
    if total_score == 0:
        category = "Low"
    elif total_score <= 3:
        category = "Medium"
    else:
        category = "High"

    if not triggered_reasons:
        triggered_reasons = ["No obvious warning signs detected. Always verify links independently."]

    return {
        "valid": True,
        "url": url,
        "score": total_score,
        "category": category,
        "reasons": triggered_reasons,
    }
