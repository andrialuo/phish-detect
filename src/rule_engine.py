"""
Phishing Detection Rule Engine
Contains all rule classes and the main rule engine
"""

import re
from typing import List, Dict, Tuple

class PhishingRule:
    """Base class for a phishing detection rule"""
    def __init__(self, name: str, severity: str, description: str):
        self.name = name
        self.severity = severity  # 'critical', 'high', 'medium', 'low'
        self.description = description
    
    def check(self, email_data: dict) -> Tuple[bool, str]:
        """
        Check if rule is triggered
        Returns: (is_triggered, evidence)
        """
        raise NotImplementedError

class SuspiciousTLDRule(PhishingRule):
    def __init__(self):
        super().__init__(
            name="Suspicious TLD",
            severity="high",
            description="Sender domain uses a suspicious top-level domain"
        )
        self.suspicious_tlds = {"ru", "cn", "br", "xyz", "top", "click", "link", "rest", "monster", "buzz", "tk", "ga", "ml", "cf"}
    
    def check(self, email_data: dict) -> Tuple[bool, str]:
        domain = email_data.get('sender_domain', '')
        if not domain:
            return False, ""
        
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in self.suspicious_tlds:
            return True, f"TLD '.{tld}' is commonly used in phishing"
        return False, ""

class BrandMismatchRule(PhishingRule):
    def __init__(self):
        super().__init__(
            name="Brand-Domain Mismatch",
            severity="critical",
            description="Display name mentions a brand not matching the sender domain"
        )
        self.brands = ["paypal", "amazon", "apple", "microsoft", "netflix", 
                      "bank", "chase", "wells fargo", "boa", "dhl", "ups", "fedex"]
    
    def check(self, email_data: dict) -> Tuple[bool, str]:
        display_name = email_data.get('display_name', '').lower()
        domain = email_data.get('sender_domain', '').lower()
        
        for brand in self.brands:
            if brand in display_name and brand not in domain:
                return True, f"Display name mentions '{brand}' but domain is '{domain}'"
        return False, ""

class ExcessiveURLsRule(PhishingRule):
    def __init__(self, threshold=5):
        super().__init__(
            name="Excessive URLs",
            severity="medium",
            description=f"Email contains more than {threshold} URLs"
        )
        self.threshold = threshold
    
    def check(self, email_data: dict) -> Tuple[bool, str]:
        num_urls = email_data.get('num_urls', 0)
        if num_urls > self.threshold:
            return True, f"Contains {num_urls} URLs (threshold: {self.threshold})"
        return False, ""

class IPAddressInURLRule(PhishingRule):
    def __init__(self):
        super().__init__(
            name="IP Address in URL",
            severity="high",
            description="URL contains IP address instead of domain name"
        )
        self.ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
    def check(self, email_data: dict) -> Tuple[bool, str]:
        urls = email_data.get('urls', [])
        for url in urls:
            if self.ip_pattern.search(url):
                return True, f"Found IP-based URL: {url}"
        return False, ""

class UrgencyKeywordsRule(PhishingRule):
    def __init__(self):
        super().__init__(
            name="Urgency Keywords",
            severity="medium",
            description="Email uses urgency-creating language"
        )
        self.urgency_words = [
            "urgent", "immediate", "action required", "verify", "suspended",
            "locked", "expire", "confirm", "click here", "act now", "limited time"
        ]
    
    def check(self, email_data: dict) -> Tuple[bool, str]:
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        text = subject + " " + body
        
        found_words = [word for word in self.urgency_words if word in text]
        if found_words:
            return True, f"Found urgency keywords: {', '.join(found_words[:3])}"
        return False, ""

class ShortenedURLRule(PhishingRule):
    def __init__(self):
        super().__init__(
            name="Shortened URL",
            severity="medium",
            description="Email contains shortened URLs that hide the real destination"
        )
        self.shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co", "short.link"]
    
    def check(self, email_data: dict) -> Tuple[bool, str]:
        urls = email_data.get('urls', [])
        for url in urls:
            for shortener in self.shorteners:
                if shortener in url.lower():
                    return True, f"Found shortened URL: {url}"
        return False, ""

class PhishingRuleEngine:
    """Main rule engine that evaluates all rules"""
    
    def __init__(self):
        self.rules: List[PhishingRule] = []
        self._initialize_rules()
    
    def _initialize_rules(self):
        """Load all rules into the engine"""
        self.rules = [
            BrandMismatchRule(),          # Critical
            IPAddressInURLRule(),         # High
            SuspiciousTLDRule(),          # High
            ShortenedURLRule(),           # Medium
            ExcessiveURLsRule(threshold=5), # Medium
            UrgencyKeywordsRule(),        # Medium
        ]
    
    def add_rule(self, rule: PhishingRule):
        """Add a custom rule to the engine"""
        self.rules.append(rule)
    
    def evaluate(self, email_data: dict) -> Dict:
        """
        Evaluate all rules against an email
        
        Returns:
            {
                'is_suspicious': bool,
                'risk_score': float (0-100),
                'triggered_rules': list of triggered rules with evidence,
                'severity_counts': dict of severity levels
            }
        """
        triggered_rules = []
        severity_weights = {
            'critical': 40,
            'high': 25,
            'medium': 10,
            'low': 5
        }
        
        risk_score = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # Evaluate each rule
        for rule in self.rules:
            is_triggered, evidence = rule.check(email_data)
            
            if is_triggered:
                triggered_rules.append({
                    'name': rule.name,
                    'severity': rule.severity,
                    'description': rule.description,
                    'evidence': evidence
                })
                risk_score += severity_weights[rule.severity]
                severity_counts[rule.severity] += 1
        
        # Cap risk score at 100
        risk_score = min(risk_score, 100)
        
        # Determine if suspicious (critical rules OR high risk score)
        has_critical = severity_counts['critical'] > 0
        is_suspicious = has_critical or risk_score >= 40
        
        return {
            'is_suspicious': is_suspicious,
            'risk_score': risk_score,
            'triggered_rules': triggered_rules,
            'severity_counts': severity_counts
        }
