# utils/parse_email.py

import email
import email.policy
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from urllib.parse import urlparse

def extract_urls_from_text(text):
    url_regex = re.compile(r'(https?://[^\s">]+)')
    return url_regex.findall(text or "")

def extract_urls_from_html(html):
    urls = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            urls.append({
                "href": a["href"],
                "text": a.get_text(strip=True)
            })
    except Exception:
        pass
    return urls

def parse_email_file(path):
    """Parse a .eml file into a structured dictionary for the rule engine."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    return parse_email_string(raw)


def parse_email_string(raw):
    msg = email.message_from_string(raw, policy=email.policy.default)

    # -----------------------
    # Headers
    # -----------------------
    from_header = msg.get("From", "") or ""
    reply_to_header = msg.get("Reply-To", "")
    message_id = msg.get("Message-ID")
    received_headers = msg.get_all("Received", []) or []

    # Extract sender domain
    from_addr = email.utils.parseaddr(from_header)[1]
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""

    # Reply-To domain
    reply_addr = None
    if reply_to_header:
        reply_addr = email.utils.parseaddr(reply_to_header)[1]
    reply_to_domain = reply_addr.split("@")[-1] if reply_addr and "@" in reply_addr else None

    # -----------------------
    # Body (text + HTML)
    # -----------------------
    body_text = ""
    html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body_text += part.get_content()
                except:
                    pass
            elif content_type == "text/html":
                try:
                    html += part.get_content()
                except:
                    pass
    else:
        if msg.get_content_type() == "text/plain":
            body_text = msg.get_content()
        elif msg.get_content_type() == "text/html":
            html = msg.get_content()

    # -----------------------
    # URL extraction
    # -----------------------
    urls = []

    # From HTML <a href=...>
    urls.extend(extract_urls_from_html(html))

    # From plain text
    for u in extract_urls_from_text(body_text):
        urls.append({"href": u, "text": u})

    # -----------------------
    # Attachments
    # -----------------------
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or ""
            attachments.append({"filename": filename})

    # -----------------------
    # Final structured object
    # -----------------------
    parsed = {
        "from_addr": from_header,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "message_id": message_id,
        "received_headers": received_headers,

        "body_text": body_text,
        "html": html,
        "urls": urls,
        "attachments": attachments,
    }
    return parsed
