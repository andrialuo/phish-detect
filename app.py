from flask import Flask, render_template, request, jsonify
import pickle
import math
from machine_learning.dataset_training import predict_single_email, explain_features

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

        pred, prob, features = predict_single_email(
            sender, subject, body, w, mean, std
        )

        reasons = explain_features(features)

        confidence = prob * 100

        if prob is None or math.isnan(prob):
            confidence = 50.0
        else:
            confidence = round(confidence, 2)


        return jsonify({
            "success": True,
            "verdict": "PHISHING" if pred else "LEGITIMATE",
            "confidence": confidence,
            "rule_score": "N/A",
            "ml_score": confidence,
            "triggered_rules": [],
            "explanation": "\n".join(reasons) if reasons else "No strong phishing indicators detected."
        })


    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

if __name__ == "__main__":
    app.run(debug=True)
