import re
from urllib.parse import urlparse
import ipaddress


MARKETING_KEYWORDS = [
    "sale", "discount", "offer", "promotion", "coupon", "deal",
    "save", "limited time", "free shipping", "order now",
    "black friday", "cyber monday", "clearance", "exclusive",
    "save up to", "new arrival", "flash sale", "קנייה", "מבצע",
    "הנחה", "חיסכון", "קידום", "הצעה", "עד", "שוק"
]

PHISHING_URGENCY = [
    "verify account", "confirm identity", "update payment",
    "unusual activity", "suspicious login", "compromised",
    "act now", "immediate action", "urgent", "expire",
    "suspended", "locked", "unauthorized", "alert",
    "לאמת", "אישור", "עדכון", "חשד", "פעילות חריגה",
    "חשבון משועבד", "מיידי", "דחוף"
]

KEYWORDS_URGENCY = [
    "urgent", "immediate", "act now", "suspended", "expire",
    "24 hours", "warning", "critical", "alert", "verify account"
]

KEYWORDS_ACTION = [
    "verify", "click here", "login", "update password", "confirm",
    "unlock", "reset password", "change password"
]

TARGET_BRANDS = ["paypal", "google", "apple", "microsoft", "amazon", "facebook", "netflix"]

SUSPICIOUS_TLDS = {".ru", ".cn", ".xyz", ".top", ".tk", ".pw", ".work", ".click"}

FREE_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"}

LEGITIMATE_DOMAINS = {
    "stripe.com", "github.com", "heroku.com", "firebase.google.com",
    "samsung.com", "il.email.samsung.com",
    "intel.com", "microsoft.com", "apple.com", "amazon.com",
    "linkedin.com", "twitter.com", "facebook.com", "adobe.com",
    "slack.com", "google.com", "aws.amazon.com", "shopify.com",
}


_EMAIL_RE = re.compile(r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')


def extract_sender_domain(sender: str) -> str:
    if not sender:
        return ""
    s = str(sender).strip().lower()
    m = _EMAIL_RE.search(s)
    if not m:
        return ""
    return (m.group(2) or "").strip().lower()


def extract_urls(text: str) -> list[str]:
    """Extract URLs from email text (basic)"""
    if not text:
        return []
    url_pattern = r'https?://[^\s)>\]]+'
    return re.findall(url_pattern, text)


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _domain_eq_or_subdomain(domain: str, legit: str) -> bool:
    domain = (domain or "").lower().strip(".")
    legit = (legit or "").lower().strip(".")
    return domain == legit or domain.endswith("." + legit)


def is_legitimate_domain(domain: str) -> bool:
    d = (domain or "").lower().strip()
    if not d:
        return False

    for legit in LEGITIMATE_DOMAINS:
        if _domain_eq_or_subdomain(d, legit):
            return True

    if d.endswith((".com", ".org", ".edu", ".gov", ".co.il", ".co.uk")):
        for brand in TARGET_BRANDS:
            if _domain_eq_or_subdomain(d, f"{brand}.com"):
                return True

    return False


def is_marketing_email(subject: str, body: str) -> float:
    full_text = f"{subject or ''} {body or ''}".lower()
    marketing_score = 0.0

    marketing_kw_count = sum(1 for kw in MARKETING_KEYWORDS if kw in full_text)
    if marketing_kw_count >= 3:
        marketing_score = 0.8
    elif marketing_kw_count >= 2:
        marketing_score = 0.6
    elif marketing_kw_count >= 1:
        marketing_score = 0.3

    product_keywords = ["product", "service", "feature", "upgrade", "new", "מוצר", "שירות"]
    if any(kw in full_text for kw in product_keywords):
        marketing_score += 0.2

    if "unsubscribe" in full_text or "הסרה מרשימה" in full_text:
        marketing_score += 0.3

    subj = (subject or "").lower()
    if "[promo" in subj or "[marketing" in subj or "[פרסומת]" in (subject or ""):
        marketing_score += 0.2

    return min(marketing_score, 1.0)

#Returns True if any URL domain mismatches sender domain (with allow-lists)
def check_domain_mismatch(sender_domain: str, urls: list[str]) -> bool:
    sender_domain = (sender_domain or "").lower().strip()
    if not sender_domain:
        return False

    if sender_domain in FREE_PROVIDERS:
        return False

    if is_legitimate_domain(sender_domain):
        return False

    whitelist = [
        "facebook.com", "linkedin.com", "twitter.com",
        "instagram.com", "waze.com", "youtube.com", "reddit.com",
        "tiktok.com", "pinterest.com", "github.com"
    ]

    for url in urls:
        try:
            parsed = urlparse(url)
            link_domain = (parsed.hostname or "").lower().strip()
            if not link_domain:
                continue

            if _domain_eq_or_subdomain(link_domain, sender_domain):
                continue

            if any(_domain_eq_or_subdomain(link_domain, w) for w in whitelist):
                continue

            return True
        except Exception:
            continue

    return False


def detect_typosquatting(sender_domain: str) -> bool:
    sender_clean = (sender_domain or "").lower()

    suspicious_patterns = [
        "gmai1", "gmaiI",
        "paypa1", "paypaI",
        "amaz0n",
        "micros0ft",
        "yaho0",
        "app1e",
    ]
    return any(pattern in sender_clean for pattern in suspicious_patterns)

#Returns a float score between 0 and 1
def check_sender_reputation(sender_domain: str, body: str) -> float:
    d = (sender_domain or "").lower()
    body_lower = (body or "").lower()
    reputation_score = 0.0

    if not d:
        return 0.0

    if is_legitimate_domain(d):
        return 0.0

    if d in FREE_PROVIDERS:
        if any(action in body_lower for action in KEYWORDS_ACTION):
            reputation_score += 0.1

    for brand in TARGET_BRANDS:
        if brand in d and not is_legitimate_domain(d):
            reputation_score += 0.15

    return min(reputation_score, 0.3)


def analyze_language_patterns(subject: str, body: str, sender: str) -> float:
    full_text = f"{subject or ''} {body or ''}".lower()
    pattern_score = 0.0

    is_marketing_prob = is_marketing_email(subject, body)
    if is_marketing_prob > 0.5:
        urgency_count = sum(1 for kw in ["urgent", "immediate", "now"] if kw in full_text)
        action_count = sum(1 for kw in ["click", "verify", "confirm"] if kw in full_text)
        if urgency_count >= 2 and action_count >= 2:
            pattern_score += 0.1
        return pattern_score

    if full_text.count("!") >= 3:
        pattern_score += 0.15

    caps_words = len([w for w in full_text.split() if w.isupper() and len(w) > 2])
    if caps_words >= 3:
        pattern_score += 0.1

    money_keywords = [
        "money", "payment", "account", "credit", "billing", "charge", "refund",
        "כסף", "תשלום", "חשבון", "אשראי", "חיוב"
    ]
    has_money = any(kw in full_text for kw in money_keywords)
    has_urgency = any(kw in full_text for kw in PHISHING_URGENCY)
    has_action = any(kw in full_text for kw in KEYWORDS_ACTION)

    if has_money and has_urgency and has_action:
        pattern_score += 0.25
    elif has_urgency and has_action:
        pattern_score += 0.15

    return min(pattern_score, 0.4)


def compute_heuristics(subject: str, body: str, sender: str) -> dict:
    subject = subject or ""
    body = body or ""
    sender = sender or ""

    full_text = f"{subject} {body}".lower()
    sender_domain = extract_sender_domain(sender)

    marketing_likelihood = is_marketing_email(subject, body)
    urls = extract_urls(full_text)

    has_ip_url = False
    has_suspicious_tld = False
    for url in urls:
        try:
            hostname = (urlparse(url).hostname or "").lower()
            if hostname and is_ip_address(hostname):
                has_ip_url = True
            if hostname and any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
                has_suspicious_tld = True
        except Exception:
            pass

    # Keyword analysis
    has_urgency = any(p in full_text for p in KEYWORDS_URGENCY)
    has_action_request = any(p in full_text for p in KEYWORDS_ACTION)

    is_typosquatting = detect_typosquatting(sender_domain)
    is_domain_mismatch = check_domain_mismatch(sender_domain, urls)
    sender_reputation = check_sender_reputation(sender_domain, body)
    language_patterns = analyze_language_patterns(subject, body, sender)

    score = 0.0

    if marketing_likelihood > 0.7:
        if is_typosquatting:
            score += 0.35
        if has_ip_url:
            score += 0.30
        if has_suspicious_tld:
            score += 0.15
        if score < 0.2 and is_domain_mismatch:
            score += 0.10
        if is_legitimate_domain(sender_domain):
            score = max(0.0, score - 0.30)
        language_patterns = 0.0
        sender_reputation = 0.0
    else:
        if is_typosquatting:
            score += 0.35
        if has_ip_url:
            score += 0.30
        if is_domain_mismatch:
            score += 0.20

        score += language_patterns
        score += sender_reputation

        if has_suspicious_tld:
            score += 0.15

    return {
        "num_urls": len(urls),
        "has_suspicious_tld": int(has_suspicious_tld),
        "has_ip_as_url": int(has_ip_url),
        "domain_mismatch": int(is_domain_mismatch),
        "typosquatting": int(is_typosquatting),
        "has_urgency_words": int(has_urgency),
        "has_action_words": int(has_action_request),
        "language_risk": round(language_patterns, 2),
        "sender_reputation_risk": round(sender_reputation, 2),
        "is_marketing_email": round(marketing_likelihood, 2),
        "rule_score": round(min(score, 1.0), 3),
        "sender_domain": sender_domain,
    }