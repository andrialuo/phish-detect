# rules/rule_engine.py

"""
Rule engine for phishing detection.

It expects a parsed_email dict with (you can adapt this to your parser):

parsed_email = {
    "from_addr": "Display Name <someone@example.com>",  # original From header
    "from_domain": "example.com",                       # domain part of From
    "reply_to_domain": "reply.com" or None,
    "message_id": "<...>" or None,
    "received_headers": [ "Received: ...", ... ],

    "body_text": "...",                                 # plain-text body
    "html": "...",                                      # optional HTML body or ""
    "urls": [                                           # list of URL dicts
        {"href": "https://example.com/login", "text": "Click here"},
        # ...
    ],
    "attachments": [                                    # list of attachment dicts
        {"filename": "invoice.docm"},
        # ...
    ],
}

run_rules(parsed_email) returns:
    total_score: float
    flags: dict[str, int]     -> rule_name -> 0/1
    results: list[RuleResult] -> detailed per-rule info
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Callable, Tuple
import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Dataclass for rule results
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    name: str
    category: str      # One of the categories in rules.txt
    hit: bool
    score: float
    explanation: str


# ---------------------------------------------------------------------------
# Constants / vocab
# ---------------------------------------------------------------------------

# Category labels to match rules.txt
CAT_HEADER = "Header/Sender Authenticity"
CAT_DOMAIN = "Domain/Address"
CAT_URL = "URL/Link"
CAT_BODY = "Body Language/Content"
CAT_ATTACH = "Attachment"

SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "loan", "fit", "work"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"}
# Very small example brand list – expand if you want
BRANDS = {"paypal", "apple", "amazon", "microsoft", "bankofamerica"}

URGENT_PHRASES = [
    "urgent action", "act immediately", "immediately", "final warning",
    "your account will be closed", "suspend your account", "limited time"
]

CRED_PHRASES = [
    "verify your account", "confirm your identity", "login to your account",
    "log in to your account", "update your payment", "password", "pin"
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "valued customer", "dear valued member"
]

EXECUTABLE_EXTS = {".exe", ".bat", ".scr", ".js", ".jar", ".ps1"}
MACRO_DOC_EXTS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z"}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _safe_lower(s: str | None) -> str:
    return s.lower() if isinstance(s, str) else ""


def _get_tld(domain: str) -> str:
    parts = domain.lower().split(".")
    return parts[-1] if parts else ""


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _has_suspicious_tld(domain: str) -> bool:
    return _get_tld(domain) in SUSPICIOUS_TLDS


def _any_match(text: str, phrases: List[str]) -> bool:
    text = text.lower()
    return any(p in text for p in phrases)


# ---------------------------------------------------------------------------
# 1. Header / Sender Authenticity rules
# ---------------------------------------------------------------------------

def rule_missing_message_id(email: Dict) -> RuleResult:
    msg_id = email.get("message_id")
    hit = not msg_id
    return RuleResult(
        name="missing_message_id",
        category=CAT_HEADER,
        hit=hit,
        score=1.5 if hit else 0.0,
        explanation="Message-ID header is missing" if hit else ""
    )


def rule_few_received_headers(email: Dict) -> RuleResult:
    received = email.get("received_headers") or []
    hit = len(received) <= 1
    return RuleResult(
        name="few_received_headers",
        category=CAT_HEADER,
        hit=hit,
        score=1.0 if hit else 0.0,
        explanation=f"Only {len(received)} Received header(s)" if hit else ""
    )


def rule_from_replyto_mismatch(email: Dict) -> RuleResult:
    from_dom = _safe_lower(email.get("from_domain"))
    reply_dom = _safe_lower(email.get("reply_to_domain"))
    hit = bool(reply_dom) and reply_dom != from_dom
    return RuleResult(
        name="from_replyto_mismatch",
        category=CAT_HEADER,
        hit=hit,
        score=1.5 if hit else 0.0,
        explanation=f"From domain {from_dom} != Reply-To domain {reply_dom}" if hit else ""
    )


# ---------------------------------------------------------------------------
# 2. Domain / Address rules
# ---------------------------------------------------------------------------

def rule_suspicious_sender_tld(email: Dict) -> RuleResult:
    dom = _safe_lower(email.get("from_domain"))
    tld = _get_tld(dom)
    hit = tld in SUSPICIOUS_TLDS
    return RuleResult(
        name="suspicious_sender_tld",
        category=CAT_DOMAIN,
        hit=hit,
        score=2.0 if hit else 0.0,
        explanation=f"Sender TLD .{tld} is in suspicious list" if hit else ""
    )


def rule_brand_mismatch_display_name(email: Dict) -> RuleResult:
    """
    Header/Sender + Domain/Address-ish:
    Display name mentions a brand, but the domain is not that brand.
    """
    from_addr = _safe_lower(email.get("from_addr"))
    dom = _safe_lower(email.get("from_domain"))
    dom_core = dom.split(".")[0] if dom else ""
    hit = False
    for b in BRANDS:
        if b in from_addr and b not in dom_core:
            hit = True
            explanation = f"Display name suggests brand '{b}' but domain is {dom}"
            break
    else:
        explanation = ""

    return RuleResult(
        name="brand_mismatch_display_name",
        category=CAT_DOMAIN,
        hit=hit,
        score=2.5 if hit else 0.0,
        explanation=explanation
    )


# ---------------------------------------------------------------------------
# 3. URL / Link rules
# ---------------------------------------------------------------------------

def rule_has_ip_url(email: Dict) -> RuleResult:
    urls = email.get("urls") or []
    ip_regex = re.compile(r"^https?://\d{1,3}(\.\d{1,3}){3}")
    hit = any(ip_regex.match(u.get("href", "")) for u in urls)
    return RuleResult(
        name="has_ip_url",
        category=CAT_URL,
        hit=hit,
        score=2.0 if hit else 0.0,
        explanation="At least one URL uses a raw IP address" if hit else ""
    )


def rule_has_url_shortener(email: Dict) -> RuleResult:
    urls = email.get("urls") or []
    hit = False
    for u in urls:
        host = _host_from_url(u.get("href", ""))
        if host in URL_SHORTENERS:
            hit = True
            break
    return RuleResult(
        name="has_url_shortener",
        category=CAT_URL,
        hit=hit,
        score=1.5 if hit else 0.0,
        explanation="Uses a known URL shortener" if hit else ""
    )


def rule_suspicious_url_tld(email: Dict) -> RuleResult:
    urls = email.get("urls") or []
    hit = False
    for u in urls:
        host = _host_from_url(u.get("href", ""))
        if host and _has_suspicious_tld(host):
            hit = True
            break
    return RuleResult(
        name="suspicious_url_tld",
        category=CAT_URL,
        hit=hit,
        score=2.0 if hit else 0.0,
        explanation="At least one URL uses a suspicious TLD" if hit else ""
    )


# ---------------------------------------------------------------------------
# 4. Body Language / Content rules
# ---------------------------------------------------------------------------

def rule_has_urgent_language(email: Dict) -> RuleResult:
    text = _safe_lower(email.get("body_text"))
    hit = _any_match(text, URGENT_PHRASES)
    return RuleResult(
        name="has_urgent_language",
        category=CAT_BODY,
        hit=hit,
        score=1.5 if hit else 0.0,
        explanation="Urgent/scare language detected" if hit else ""
    )


def rule_has_credential_request(email: Dict) -> RuleResult:
    text = _safe_lower(email.get("body_text"))
    hit = _any_match(text, CRED_PHRASES)
    return RuleResult(
        name="has_credential_request",
        category=CAT_BODY,
        hit=hit,
        score=2.0 if hit else 0.0,
        explanation="Text asks for credentials or sensitive info" if hit else ""
    )


def rule_generic_greeting(email: Dict) -> RuleResult:
    text = _safe_lower(email.get("body_text"))
    hit = _any_match(text, GENERIC_GREETINGS)
    return RuleResult(
        name="generic_greeting",
        category=CAT_BODY,
        hit=hit,
        score=1.0 if hit else 0.0,
        explanation="Generic greeting (e.g., 'Dear customer')" if hit else ""
    )


def rule_many_exclamation_marks(email: Dict) -> RuleResult:
    text = email.get("body_text") or ""
    count = text.count("!")
    hit = count >= 3
    return RuleResult(
        name="many_exclamation_marks",
        category=CAT_BODY,
        hit=hit,
        score=0.5 if hit else 0.0,
        explanation=f"Body contains {count} exclamation marks" if hit else ""
    )


# ---------------------------------------------------------------------------
# 5. Attachment rules (optional but implemented)
# ---------------------------------------------------------------------------

def rule_has_executable_attachment(email: Dict) -> RuleResult:
    atts = email.get("attachments") or []
    hit = False
    for a in atts:
        fname = _safe_lower(a.get("filename", ""))
        if any(fname.endswith(ext) for ext in EXECUTABLE_EXTS):
            hit = True
            break
    return RuleResult(
        name="has_executable_attachment",
        category=CAT_ATTACH,
        hit=hit,
        score=3.0 if hit else 0.0,
        explanation="Attachment with executable extension present" if hit else ""
    )


def rule_has_macro_doc_attachment(email: Dict) -> RuleResult:
    atts = email.get("attachments") or []
    hit = False
    for a in atts:
        fname = _safe_lower(a.get("filename", ""))
        if any(fname.endswith(ext) for ext in MACRO_DOC_EXTS):
            hit = True
            break
    return RuleResult(
        name="has_macro_doc_attachment",
        category=CAT_ATTACH,
        hit=hit,
        score=2.5 if hit else 0.0,
        explanation="Macro-enabled Office document attachment present" if hit else ""
    )


def rule_has_suspicious_archive(email: Dict) -> RuleResult:
    """
    Archive attachment with a very generic name like 'invoice', 'payment', 'statement'.
    """
    atts = email.get("attachments") or []
    suspicious_keywords = {"invoice", "payment", "statement"}
    hit = False
    for a in atts:
        fname = _safe_lower(a.get("filename", ""))
        if any(fname.endswith(ext) for ext in ARCHIVE_EXTS):
            if any(k in fname for k in suspicious_keywords):
                hit = True
                break
    return RuleResult(
        name="has_suspicious_archive",
        category=CAT_ATTACH,
        hit=hit,
        score=1.5 if hit else 0.0,
        explanation="Suspiciously named archive attachment present" if hit else ""
    )


# ---------------------------------------------------------------------------
# Rule registry & main API
# ---------------------------------------------------------------------------

RuleFn = Callable[[Dict], RuleResult]

ALL_RULES: List[RuleFn] = [
    # 1. Header / Sender Authenticity
    rule_missing_message_id,
    rule_few_received_headers,
    rule_from_replyto_mismatch,

    # 2. Domain / Address
    rule_suspicious_sender_tld,
    rule_brand_mismatch_display_name,

    # 3. URL / Link
    rule_has_ip_url,
    rule_has_url_shortener,
    rule_suspicious_url_tld,

    # 4. Body Language / Content
    rule_has_urgent_language,
    rule_has_credential_request,
    rule_generic_greeting,
    rule_many_exclamation_marks,

    # 5. Attachment
    rule_has_executable_attachment,
    rule_has_macro_doc_attachment,
    rule_has_suspicious_archive,
]


def run_rules(parsed_email: Dict) -> Tuple[float, Dict[str, int], List[RuleResult]]:
    """
    Run all rules on a parsed_email dict.

    Returns:
        total_score: float
        flags: {rule_name: 0 or 1}
        results: list of RuleResult
    """
    total_score = 0.0
    flags: Dict[str, int] = {}
    results: List[RuleResult] = []

    for rule_fn in ALL_RULES:
        res = rule_fn(parsed_email)
        results.append(res)
        flags[res.name] = int(bool(res.hit))
        total_score += res.score

    return total_score, flags, results

if __name__ == "__main__":
    from utils.parse_email import parse_email_file

    parsed = parse_email_file("example.eml")
    total, flags, results = run_rules(parsed)

    print("Total Score:", total)
    print("Flags:", flags)
    for r in results:
        if r.hit:
            print(f"[HIT] {r.name}: {r.explanation}")
