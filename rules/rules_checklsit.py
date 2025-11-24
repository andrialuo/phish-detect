# ============================================================
# Rule Engine (Expanded Minimal Version) - could also go in CLI folder
# ============================================================
# 1. check for urgent wording
# 2. detect suspicious TLDs
# 3. detect lookalike domains
# 4. detect raw IP URLs
# 5. count URLs
# 6. output rule-based score

# ✔ The goal is to catch phishing behavior tricks
# ✔ This logic applies at runtime, not during training

def has_urgent_language(text):
    urgent_words = [
        "urgent", "immediately", "verify now",
        "login now", "your account", "restricted",
        "suspended", "reset your password"
    ]
    return any(word in text.lower() for word in urgent_words)


def has_suspicious_url(text):
    """
    Detects URLs with suspicious top-level domains (TLDs)
    such as .xyz, .tk, etc. These TLDs are commonly used
    for phishing because they are cheap and unregulated.
    """
    pattern = r"http[s]?://[^\s]+"
    urls = re.findall(pattern, text)

    suspicious_tlds = [".xyz", ".tk", ".top", ".click", ".ml", ".zip"]
    for url in urls:
        if any(tld in url for tld in suspicious_tlds):
            return True
    return False


def has_lookalike_domain(text):
    """
    Detects lookalike domains that replace letters with numbers,
    such as paypa1.com, faceb00k.com, or micr0soft.com.
    These mimic trusted services to trick users.
    """
    pattern = r"http[s]?://[^\s]+"
    urls = re.findall(pattern, text)

    # Common character substitutions attackers use
    substitutions = ["0", "1", "3", "5", "7"]  # O->0, l->1, E->3, S->5...

    for url in urls:
        domain = url.split("/")[2] if "/" in url else url
        # If domain contains suspicious substitutions AND letters
        if any(num in domain for num in substitutions) and any(letter.isalpha() for letter in domain):
            return True
    return False


def has_ip_address_url(text):
    """
    Detects URLs that directly use IP addresses.
    Legitimate companies almost never send raw IP links.
    """
    ip_pattern = r"http[s]?://\d{1,3}(\.\d{1,3}){3}"
    return re.search(ip_pattern, text) is not None


def has_many_urls(text):
    """
    Flags emails that contain an unusually high number of URLs.
    Phishing campaigns often include many redundant or tracking links.
    """
    pattern = r"http[s]?://[^\s]+"
    urls = re.findall(pattern, text)
    return len(urls) >= 5  # threshold can be adjusted


def run_rules(text):
    """
    Run rule-based checks and return (score, reasons list).
    Each triggered rule increases suspicion.
    """
    score = 0
    reasons = []

    if has_urgent_language(text):
        score += 1
        reasons.append("Urgent wording detected")

    if has_suspicious_url(text):
        score += 1
        reasons.append("Suspicious TLD detected in URL")

    if has_lookalike_domain(text):
        score += 1
        reasons.append("Lookalike domain detected")

    if has_ip_address_url(text):
        score += 1
        reasons.append("Raw IP address URL detected")

    if has_many_urls(text):
        score += 1
        reasons.append("Unusually high number of URLs detected")

    return score, reasons
