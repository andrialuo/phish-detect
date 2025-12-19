from flask import Flask, render_template, request, jsonify
import pickle
import math
from machine_learning.dataset_training import predict_single_email, explain_features
from rules.rule_engine import run_rules
from urllib.parse import urlparse
import re

def extract_urls_from_text(text):
    pattern = r"http[s]?://[^\s]+"
    urls = re.findall(pattern, text)
    return [{"href": u} for u in urls]

app = Flask(__name__)

with open("models/logreg_model.pkl", "rb") as f:
    model = pickle.load(f)

w = model["weights"]
mean = model["mean"]
std = model["std"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        sender = request.form["sender"]
        subject = request.form["subject"]
        body = request.form["body"]

        # extract sender domain
        from_domain = ""
        if "@" in sender:
            from_domain = sender.split("@")[-1].strip("> ")

        parsed_email = {
            "from_addr": sender,
            "from_domain": from_domain,
            "reply_to_domain": None,
            "message_id": None,
            "received_headers": [],

            "body_text": subject + " " + body,
            "html": "",
            "urls": extract_urls_from_text(body),
            "attachments": [],
        }

        pred, prob, features = predict_single_email(
            sender, subject, body, w, mean, std
        )

        reasons = explain_features(features)
        rule_score, rule_flags, rule_results = run_rules(parsed_email)

        triggered_rules = [
            {
                "severity": "high" if r.score >= 2 else "medium",
                "name": r.name.replace("_", " ").title(),
                "evidence": r.explanation
            }
            for r in rule_results if r.hit
        ]


        confidence = prob * 100

        if prob is None or math.isnan(prob):
            confidence = 50.0
        else:
            confidence = round(confidence, 2)

        normalized_rule_score = round((rule_score / 15) * 100, 1)

        return jsonify({
            "success": True,
            "verdict": "PHISHING" if (pred or rule_score >= 4) else "LEGITIMATE",
            "confidence": confidence,
            "rule_score": normalized_rule_score,
            "ml_score": confidence,
            "triggered_rules": triggered_rules,
            "explanation": "\n".join(reasons) if reasons else "No strong phishing indicators detected."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

if __name__ == "__main__":
    app.run(debug=True)
