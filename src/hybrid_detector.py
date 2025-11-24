"""
Hybrid Phishing Detector combining rules and ML
"""

import pandas as pd
from typing import Dict, Tuple
from .feature_extraction import extract_ml_features

class HybridPhishingDetector:
    """
    Combines rule-based detection with ML for robust phishing detection
    """
    
    def __init__(self, ml_model, rule_engine):
        self.ml_model = ml_model
        self.rule_engine = rule_engine
        
        # Thresholds
        self.high_risk_threshold = 70  # Rule score that overrides ML
        self.ml_threshold = 0.6        # ML probability threshold
    
    def detect(self, email_data: dict) -> Dict:
        """
        Main detection method
        
        Returns:
            {
                'verdict': 'PHISHING' or 'LEGITIMATE',
                'confidence': float (0-1),
                'rule_score': float (0-100),
                'ml_score': float (0-1),
                'method': 'rules' or 'ml' or 'hybrid',
                'triggered_rules': list,
                'explanation': str
            }
        """
        # Step 1: Evaluate rules
        rule_result = self.rule_engine.evaluate(email_data)
        rule_score = rule_result['risk_score']
        triggered_rules = rule_result['triggered_rules']
        
        # Step 2: Check for critical rules (instant phishing verdict)
        if rule_result['severity_counts']['critical'] > 0:
            return {
                'verdict': 'PHISHING',
                'confidence': 0.95,
                'rule_score': rule_score,
                'ml_score': None,
                'method': 'rules (critical)',
                'triggered_rules': triggered_rules,
                'explanation': self._explain_critical_rules(triggered_rules)
            }
        
        # Step 3: Run ML model
        ml_features = extract_ml_features(email_data)
        features_df = pd.DataFrame([ml_features])
        
        ml_prediction = self.ml_model.predict(features_df)[0]
        ml_probability = self.ml_model.predict_proba(features_df)[0][1]
        
        # Step 4: Make final decision based on combination
        verdict, confidence, method = self._combine_scores(
            rule_score, ml_probability, triggered_rules
        )
        
        explanation = self._generate_explanation(
            verdict, rule_score, ml_probability, triggered_rules, method
        )
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'rule_score': rule_score,
            'ml_score': ml_probability,
            'method': method,
            'triggered_rules': triggered_rules,
            'explanation': explanation
        }
    
    def _combine_scores(self, rule_score: float, ml_prob: float, 
                       triggered_rules: list) -> Tuple[str, float, str]:
        """
        Combine rule and ML scores for final verdict
        """
        
        # High confidence from rules
        if rule_score >= self.high_risk_threshold:
            return 'PHISHING', 0.85, 'rules (high confidence)'
        
        # Low rule score, trust ML
        if rule_score < 20:
            verdict = 'PHISHING' if ml_prob >= self.ml_threshold else 'LEGITIMATE'
            return verdict, ml_prob, 'ml (primary)'
        
        # Medium rule score: hybrid approach
        # Weighted combination: 60% ML, 40% rules
        combined_score = (0.6 * ml_prob) + (0.4 * (rule_score / 100))
        
        if combined_score >= 0.5:
            return 'PHISHING', combined_score, 'hybrid'
        else:
            return 'LEGITIMATE', 1 - combined_score, 'hybrid'
    
    def _explain_critical_rules(self, triggered_rules: list) -> str:
        critical = [r for r in triggered_rules if r['severity'] == 'critical']
        lines = ["Email flagged by CRITICAL rules:"]
        for rule in critical:
            lines.append(f"  • {rule['name']}: {rule['evidence']}")
        return "\n".join(lines)
    
    def _generate_explanation(self, verdict: str, rule_score: float, 
                            ml_prob: float, triggered_rules: list, method: str) -> str:
        """Generate human-readable explanation"""
        lines = []
        lines.append(f"VERDICT: {verdict}")
        lines.append(f"Detection Method: {method}")
        lines.append("")
        lines.append(f"Rule-based Risk Score: {rule_score}/100")
        if ml_prob is not None:
            lines.append(f"ML Phishing Probability: {ml_prob:.2%}")
        lines.append("")
        
        if triggered_rules:
            lines.append("Detected Suspicious Patterns:")
            for rule in sorted(triggered_rules, 
                             key=lambda x: ['critical','high','medium','low'].index(x['severity'])):
                lines.append(f"  [{rule['severity'].upper()}] {rule['name']}")
                lines.append(f"    → {rule['evidence']}")
        else:
            lines.append("No suspicious patterns detected by rules")
            if ml_prob is not None:
                lines.append(f"ML model assessed phishing probability at {ml_prob:.2%}")
        
        return "\n".join(lines)
