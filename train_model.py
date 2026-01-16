import pandas as pd
import numpy as np
import re
import joblib
import math
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from data_loader import DataLoader

class PhishingDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_names = [
            'url_length', 'hostname_length', 'path_length', 'fd_length', 'tld_length',
            'count_dash', 'count_at', 'count_question', 'count_percent', 'count_dot',
            'count_equal', 'count_ampersand', 'count_underscore',
            'count_digits', 'count_alpha',
            'is_ip', 'short_url', 'https_token', 'sensitive_words', 'entropy'
        ]

    def get_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_features(self, url):
        """
        Extracts comprehensive lexical features from a URL based on common phishing indicators.
        """
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        
        # Feature extraction logic
        features = {}
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(path)
        features['fd_length'] = len(path.split('/')[1]) if len(path.split('/')) > 1 else 0
        
        # TLD length (approximate)
        tld = hostname.split('.')[-1] if '.' in hostname else ''
        features['tld_length'] = len(tld)
        
        # Character Counts
        features['count_dash'] = url.count('-')
        features['count_at'] = url.count('@')
        features['count_question'] = url.count('?')
        features['count_percent'] = url.count('%')
        features['count_dot'] = url.count('.')
        features['count_equal'] = url.count('=')
        features['count_ampersand'] = url.count('&')
        features['count_underscore'] = url.count('_')
        
        features['count_digits'] = sum(c.isdigit() for c in url)
        features['count_alpha'] = sum(c.isalpha() for c in url)
        
        # Boolean / Binary Indicators
        features['is_ip'] = 1 if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0
        
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'ow.ly', 'lc.chat']
        features['short_url'] = 1 if any(s in hostname for s in shorteners) else 0
        
        features['https_token'] = 1 if 'https' in parsed.scheme else 0
        
        sensitive = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'password']
        features['sensitive_words'] = sum(1 for w in sensitive if w in url.lower())
        
        # Entropy
        features['entropy'] = self.get_entropy(url)
        
        # Return list in specific order
        return [features[key] for key in self.feature_names]

    def explain_prediction(self, features_list, prediction, url=None):
        """
        Simple rule-based explanation based on feature values.
        """
        reasons = []
        # Map list back to dict for easier logic
        feats = dict(zip(self.feature_names, features_list))

        if prediction == 1: # Malicious
            if feats.get('is_ip', 0) == 1:
                reasons.append("Hostname is an IP address (Indicator #9).")
            if feats.get('short_url', 0) == 1:
                reasons.append("Uses a URL shortening service (Indicator #8).")
            if feats.get('count_at', 0) > 0:
                reasons.append("Contains '@' symbol, often used for obfuscation (Indicator #48).")
            if feats.get('sensitive_words', 0) > 0:
                reasons.append("Contains sensitive keywords like 'login' or 'secure' (Indicator #16).")
            if feats.get('entropy', 0) > 4.5:
                reasons.append("High randomness (entropy) in URL structure (Indicator #37).")
            if feats.get('count_dash', 0) > 3:
                reasons.append("Excessive hyphens in domain (Indicator #13).")
            if feats.get('url_length', 0) > 75:
                reasons.append("URL is suspiciously long (Indicator #36).")
            if not reasons:
                reasons.append("Detected suspicious patterns matching known phishing sites.")
        else:
            reasons.append("URL structure appears legitimate.")
            
        return reasons

    def train(self):
        loader = DataLoader()
        df = loader.get_data()
        
        print("Extracting features...")
        X = np.array([self.extract_features(url) for url in df['url']])
        y = df['label'].values
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        print("Training Random Forest...")
        self.model.fit(X_train, y_train)
        
        preds = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, preds)
        print(f"Model Accuracy: {accuracy}")
        print(classification_report(y_test, preds))
        
        # Save model
        joblib.dump(self.model, 'phishing_model.pkl')
        print("Model saved to phishing_model.pkl")
        return accuracy

if __name__ == "__main__":
    detector = PhishingDetector()
    detector.train()
