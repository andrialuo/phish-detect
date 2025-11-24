"""
Feature extraction utilities for phishing detection
"""

import re
from typing import Dict, List

def extract_email_data(sender: str, subject: str, body: str, urls: List[str] = None) -> Dict:
    """
    Extract structured data from email components
    
    Args:
        sender: Email sender string (e.g., "John Doe <john@example.com>")
        subject: Email subject line
        body: Email body text
        urls: List of URLs found in the email (optional)
    
    Returns:
        Dictionary with extracted features
    """
    # Extract domain from sender
    match = re.search(r'@([^>]+)>?', str(sender))
    domain = match.group(1).lower() if match else ""
    
    # Extract display name
    if "<" in str(sender):
        display_name = str(sender).split("<")[0].strip().strip('"').lower()
    else:
        display_name = str(sender).lower()
    
    # Parse URLs if provided as string
    if urls is None:
        urls = extract_urls_from_text(body)
    elif isinstance(urls, str):
        try:
            urls = eval(urls)
        except:
            urls = []
    
    return {
        'sender': sender,
        'sender_domain': domain,
        'display_name': display_name,
        'subject': subject,
        'body': body,
        'urls': urls,
        'num_urls': len(urls)
    }

def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from text using regex"""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)

def extract_ml_features(email_data: Dict) -> Dict:
    """
    Extract features for ML model
    
    Returns features matching the training data format
    """
    features = {
        'num_urls': email_data.get('num_urls', 0),
        'suspicious_tld': check_suspicious_tld(email_data.get('sender_domain', '')),
        'brand_mismatch': check_brand_mismatch(
            email_data.get('display_name', ''),
            email_data.get('sender_domain', '')
        )
    }
    return features

def check_suspicious_tld(domain: str) -> int:
    """Check if domain uses suspicious TLD"""
    suspicious_tlds = {
        "ru", "cn", "br", "xyz", "top", "click", "link", "rest",
        "monster", "buzz", "tk", "ga", "ml", "cf"
    }
    tld = domain.split('.')[-1] if '.' in domain else ''
    return 1 if tld in suspicious_tlds else 0

def check_brand_mismatch(display_name: str, domain: str) -> int:
    """Check if display name mentions brand not in domain"""
    brands = [
        "paypal", "amazon", "apple", "microsoft", "netflix",
        "bank", "chase", "wells fargo", "boa", "dhl", "ups", "fedex"
    ]
    
    display_name = display_name.lower()
    domain = domain.lower()
    
    for brand in brands:
        if brand in display_name and brand not in domain:
            return 1
    return 0
