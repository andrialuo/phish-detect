"""
Flask web application for phishing email detection
"""

from flask import Flask, render_template, request, jsonify
import pickle
import os
from src.rule_engine import PhishingRuleEngine
from src.hybrid_detector import HybridPhishingDetector
from src.feature_extraction import extract_email_data, extract_urls_from_text

app = Flask(__name__)

# Load trained model
MODEL_PATH = os.path.join('models', 'trained_model.pkl')
with open(MODEL_PATH, 'rb') as f:
    ml_model = pickle.load(f)

# Initialize detector
rule_engine = PhishingRuleEngine()
detector = HybridPhishingDetector(ml_model, rule_engine)

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze email for phishing"""
    try:
        # Get form data
        sender = request.form.get('sender', '')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        
        # Extract URLs from body
        urls = extract_urls_from_text(body)
        
        # Create email data structure
        email_data = extract_email_data(sender, subject, body, urls)
        
        # Detect phishing
        result = detector.detect(email_data)
        
        # Format response
        response = {
            'success': True,
            'verdict': result['verdict'],
            'confidence': round(result['confidence'] * 100, 1),
            'rule_score': result['rule_score'],
            'ml_score': round(result['ml_score'] * 100, 1) if result['ml_score'] else None,
            'method': result['method'],
            'triggered_rules': result['triggered_rules'],
            'explanation': result['explanation'],
            'num_urls': len(urls),
            'urls_found': urls[:5]  # Show first 5 URLs
        }
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for programmatic access"""
    try:
        data = request.get_json()
        
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        body = data.get('body', '')
        urls = data.get('urls', [])
        
        # Extract email data
        email_data = extract_email_data(sender, subject, body, urls)
        
        # Detect
        result = detector.detect(email_data)
        
        return jsonify({
            'success': True,
            'verdict': result['verdict'],
            'confidence': result['confidence'],
            'rule_score': result['rule_score'],
            'ml_score': result['ml_score'],
            'triggered_rules': result['triggered_rules']
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
