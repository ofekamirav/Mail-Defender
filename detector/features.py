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
    "samsung.com", "samsung-mena@il.email.samsung.com",
    "intel.com", "microsoft.com", "apple.com", "amazon.com",
    "linkedin.com", "twitter.com", "facebook.com", "adobe.com",
    "slack.com", "google.com", "aws.amazon.com", "shopify.com"
}


def extract_urls(text: str) -> list[str]:
    """Extract URLs from email text"""
    if not text:
        return []
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(url_pattern, text)

def is_ip_address(hostname: str) -> bool:
    """Check if hostname is an IP address"""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def is_legitimate_domain(domain: str) -> bool:
    """Check if domain is from a known legitimate company"""
    domain_lower = domain.lower()
    
    # Exact matches
    if any(legit in domain_lower for legit in LEGITIMATE_DOMAINS):
        return True
    
    if domain_lower.endswith((".com", ".org", ".edu", ".gov", ".co.il", ".co.uk")):
        for brand in TARGET_BRANDS:
            if brand in domain_lower:
                if f"{brand}.com" in domain_lower:
                    return True
    
    return False

def is_marketing_email(subject: str, body: str) -> float:
    """
    Determine likelihood email is legitimate marketing (0-1).
    Higher = more likely marketing email.
    """
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
    
    if "[promo" in subject.lower() or "[marketing" in subject.lower() or "[פרסומת]" in subject:
        marketing_score += 0.2
    
    return min(marketing_score, 1.0)

def check_domain_mismatch(sender_domain: str, urls: list[str]) -> bool:
    """Check if links go to different domain than sender"""
    if not sender_domain:
        return False
    
    if sender_domain in FREE_PROVIDERS:
        return False
    
    if is_legitimate_domain(sender_domain):
        return False

    for url in urls:
        try:
            parsed = urlparse(url)
            link_domain = parsed.hostname or ""
            if not link_domain:
                continue

            if sender_domain in link_domain:
                continue

            whitelist = [
                "facebook.com", "linkedin.com", "twitter.com", 
                "instagram.com", "waze.com", "youtube.com", "reddit.com",
                "tiktok.com", "pinterest.com", "github.com"
            ]
            if any(w in link_domain for w in whitelist):
                continue

            return True
        except:
            continue

    return False

def detect_typosquatting(sender_domain: str) -> bool:
    """Detect visual typosquatting attacks"""
    sender_clean = sender_domain.lower()
    
    suspicious_patterns = [
        "gmai1", "gmaiI",  
        "paypa1", "paypaI",  
        "amaz0n",  
        "micros0ft",  
        "yaho0",  
        "app1e",  
    ]

    return any(pattern in sender_clean for pattern in suspicious_patterns)

def check_sender_reputation(sender: str, body: str) -> float:
    """
    Score sender reputation. Returns 0-1 float.
    Higher = more suspicious.
    """
    sender_lower = (sender or "").lower()
    body_lower = (body or "").lower()
    
    reputation_score = 0.0
    
    if is_legitimate_domain(sender_lower):
        return 0.0
    
    if any(provider in sender_lower for provider in FREE_PROVIDERS):
        if any(action in body_lower for action in KEYWORDS_ACTION):
            reputation_score += 0.1
    
    for brand in TARGET_BRANDS:
        if brand in sender_lower and not is_legitimate_domain(sender_lower):
            reputation_score += 0.15
    
    return min(reputation_score, 0.3)

def analyze_language_patterns(subject: str, body: str, sender: str) -> float:
    """
    Analyze language patterns for phishing indicators.
    Returns 0-1 float.
    """
    full_text = f"{subject or ''} {body or ''}".lower()
    sender_lower = (sender or "").lower()
    
    pattern_score = 0.0
    
    is_marketing_prob = is_marketing_email(subject, body)
    if is_marketing_prob > 0.5:
        
        urgency_count = sum(1 for kw in ["urgent", "immediate", "now"] if kw in full_text)
        action_count = sum(1 for kw in ["click", "verify", "confirm"] if kw in full_text)
        
        if urgency_count >= 2 and action_count >= 2:
            pattern_score += 0.1
        
        return pattern_score
    
    exclamation_count = full_text.count("!")
    if exclamation_count >= 3:
        pattern_score += 0.15
    
    caps_words = len([w for w in full_text.split() if w.isupper() and len(w) > 2])
    if caps_words >= 3:
        pattern_score += 0.1
    
    money_keywords = ["money", "payment", "account", "credit", "billing", "charge", "refund",
                      "כסף", "תשלום", "חשבון", "אשראי", "חיוב"]
    has_money = any(kw in full_text for kw in money_keywords)
    has_urgency = any(kw in full_text for kw in PHISHING_URGENCY)
    has_action = any(kw in full_text for kw in KEYWORDS_ACTION)
    
    if has_money and has_urgency and has_action:
        pattern_score += 0.25
    elif has_urgency and has_action:
        pattern_score += 0.15
    
    return min(pattern_score, 0.4)


def compute_heuristics(subject: str, body: str, sender: str) -> dict:
    """
    Compute heuristic features for email classification.
    Significantly improved to reduce false positives on marketing emails.
    """
    subject = subject or ""
    body = body or ""
    sender = (sender or "").lower()
    full_text = f"{subject} {body}".lower()
    
    sender_domain = sender.split("@")[-1] if "@" in sender else ""
    
    marketing_likelihood = is_marketing_email(subject, body)
    
    if marketing_likelihood > 0.7:
        
        urls = extract_urls(full_text)
        has_ip_url = False
        has_suspicious_tld = False
        
        for url in urls:
            try:
                hostname = urlparse(url).hostname or ""
                if is_ip_address(hostname):
                    has_ip_url = True
                if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    has_suspicious_tld = True
            except:
                pass
        
        score = 0.0
        
        if detect_typosquatting(sender_domain):
            score += 0.35
        if has_ip_url:
            score += 0.30
        if has_suspicious_tld:
            score += 0.15
        
        if score < 0.2 and check_domain_mismatch(sender_domain, urls):
            score += 0.10
        
        if is_legitimate_domain(sender_domain):
            score = max(0, score - 0.3)
        
        return {
            "num_urls": len(urls),
            "has_suspicious_tld": int(has_suspicious_tld),
            "has_ip_as_url": int(has_ip_url),
            "domain_mismatch": int(check_domain_mismatch(sender_domain, urls)),
            "typosquatting": int(detect_typosquatting(sender_domain)),
            "has_urgency_words": 0,  
            "has_action_words": 0,   
            "language_risk": 0.0,
            "sender_reputation_risk": 0.0,
            "is_marketing_email": round(marketing_likelihood, 2),
            "rule_score": round(min(score, 1.0), 3)
        }
        
    urls = extract_urls(full_text)
    num_urls = len(urls)
    
    has_suspicious_tld = False
    has_ip_url = False
    
    for url in urls:
        try:
            hostname = urlparse(url).hostname or ""
            if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
                has_suspicious_tld = True
            if is_ip_address(hostname):
                has_ip_url = True
        except:
            pass
    
    # Keyword analysis
    has_urgency = any(p in full_text for p in KEYWORDS_URGENCY)
    has_action_request = any(p in full_text for p in KEYWORDS_ACTION)
    
    # Suspicious indicators
    is_typosquatting = detect_typosquatting(sender_domain)
    is_domain_mismatch = check_domain_mismatch(sender_domain, urls)
    sender_reputation = check_sender_reputation(sender, body)
    language_patterns = analyze_language_patterns(subject, body, sender)
    
    # Calculate heuristic score
    score = 0.0
    
    # Critical indicators
    if is_typosquatting:
        score += 0.35
    if has_ip_url:
        score += 0.30
    if is_domain_mismatch:
        score += 0.20
    
    # Pattern analysis
    score += language_patterns
    score += sender_reputation
    
    # Additional factors
    if has_suspicious_tld:
        score += 0.15
    
    return {
        "num_urls": num_urls,
        "has_suspicious_tld": int(has_suspicious_tld),
        "has_ip_as_url": int(has_ip_url),
        "domain_mismatch": int(is_domain_mismatch),
        "typosquatting": int(is_typosquatting),
        "has_urgency_words": int(has_urgency),
        "has_action_words": int(has_action_request),
        "language_risk": round(language_patterns, 2),
        "sender_reputation_risk": round(sender_reputation, 2),
        "is_marketing_email": round(marketing_likelihood, 2),
        "rule_score": round(min(score, 1.0), 3)
    }