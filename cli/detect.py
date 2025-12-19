# goal: python cli/detect.py --email path/to/email.txt
# === PHISHING DETECTOR RESULT ===
# Rule-based score: 2
# Rule reasons:
#  - Urgent wording detected
#  - Suspicious URL pattern

# ML Probability: 0.87
# FINAL VERDICT: PHISHING

import re
import argparse
import joblib

# ============================================================
# Text loader + cleaner
# ============================================================

def load_email_text(path):
    """Load raw email text from a .txt file."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def clean_text(text):
    """Basic cleaning to match preprocessing."""
    text = text.lower()
    text = re.sub(r"<.*?>", " ", text)        # remove HTML tags
    text = re.sub(r"http\S+", " url ", text)  # normalize URLs
    text = re.sub(r"[^a-z0-9\s:/._-]", " ", text)  # remove weird symbols
    text = re.sub(r"\s+", " ", text)          # collapse whitespace
    return text.strip()


# ============================================================
# Rule Engine
# ============================================================

def has_urgent_language(text):
    urgent_words = [
        "urgent", "immediately", "verify now", 
        "login now", "your account", "restricted",
        "suspended", "reset your password"
    ]
    return any(word in text.lower() for word in urgent_words)


def has_suspicious_url(text):
    pattern = r"http[s]?://[^\s]+"
    urls = re.findall(pattern, text)

    suspicious_tlds = [".xyz", ".tk", ".top", ".click", ".ml", ".zip"]
    for url in urls:
        if any(tld in url for tld in suspicious_tlds):
            return True
    return False


def run_rules(text):
    """Run rule-based checks and return (score, reasons list)."""
    score = 0
    reasons = []

    if has_urgent_language(text):
        score += 1
        reasons.append("Urgent wording detected")

    if has_suspicious_url(text):
        score += 1
        reasons.append("Suspicious URL pattern detected")

    return score, reasons


# ============================================================
# ML Model Loader + Prediction
# ============================================================

def load_ml_components():
    """Load vectorizer + trained ML model."""
    vectorizer = joblib.load("ml/vectorizer.pkl") # ******NEED EDIT
    model = joblib.load("ml/model.pkl") # ******NEED EDIT
    return vectorizer, model


def ml_predict_proba(text, vectorizer, model):
    """Return the probability that an email is phishing."""
    X = vectorizer.transform([text])
    return model.predict_proba(X)[0][1]


# ============================================================
# CLI Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Phishing Email Detector CLI")
    parser.add_argument("--email", type=str, required=True,
                        help="Path to the email .txt file")

    args = parser.parse_args()

    # Load + clean email
    raw_text = load_email_text(args.email)
    cleaned = clean_text(raw_text)

    # Rule-based detection
    rule_score, reasons = run_rules(cleaned)

    # ML Model Prediction
    vectorizer, model = load_ml_components()
    ml_proba = ml_predict_proba(cleaned, vectorizer, model)

    # Final decision logic
    verdict = "PHISHING" if (rule_score > 0 or ml_proba > 0.7) else "LEGITIMATE"

    # ============================
    # Output Results
    # ============================

    print("\n=== PHISHING DETECTOR RESULT ===")
    print(f"Rule-based Score: {rule_score}")

    if reasons:
        print("Rule Reasons:")
        for r in reasons:
            print(f" - {r}")

    print(f"\nML Probability: {ml_proba:.3f}")
    print(f"\nFINAL VERDICT: {verdict}\n")


if __name__ == "__main__":
    main()

# additions
# 🔍 Minor Improvements (Optional)

# These are not required, but make it nicer:

# 1. Add color output (red for phishing, green for legit)
# 2. Add support for .eml real emails (header parsing!)
#   If your dataset includes raw emails.
# 3. Add a “verbose mode”
#   python detect.py --email test.txt --verbose
# 4. Add interactive mode
#   python detect.py --interactive