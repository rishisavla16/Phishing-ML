from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import os
import csv
import requests
from train_model import PhishingDetector

app = Flask(__name__)

# Load Model
detector = PhishingDetector()
try:
    model = joblib.load('phishing_model.pkl')
    detector.model = model
    print("Model loaded successfully.")
except:
    print("Model not found. It will be trained on the first request.")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'})

    # Normalize URL (ensure scheme exists) for consistent feature extraction
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Validate if URL is reachable
    try:
        # Ensure scheme exists for the request
        target_url = url
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        requests.get(target_url, timeout=5, headers={'User-Agent': 'PhishingDetector/1.0'})
    except requests.RequestException:
        return jsonify({'error': 'URL is unreachable or invalid.'})

    # 1. Extract Features
    features = detector.extract_features(url)
    
    # 2. Predict
    try:
        prediction = detector.model.predict([features])[0]
        prob = detector.model.predict_proba([features])[0][1] # Probability of being malicious
    except (ValueError, AttributeError):
        # Handle feature mismatch or model not fitted
        print("Model mismatch or not trained. Retraining now...")
        detector.train()
        prediction = detector.model.predict([features])[0]
        prob = detector.model.predict_proba([features])[0][1]
    
    # 3. Explain
    explanation = detector.explain_prediction(features, prediction, url)
    
    result = {
        'url': url,
        'is_malicious': bool(prediction),
        'confidence': float(prob),
        'explanation': explanation
    }
    return jsonify(result)

@app.route('/retrain', methods=['POST'])
def retrain_model():
    """
    Manually trigger model retraining.
    """
    accuracy = detector.train()
    # Reload the model into memory
    detector.model = joblib.load('phishing_model.pkl')
    return jsonify({'status': 'success', 'message': f'Model retrained with new data! Accuracy: {accuracy:.2%}'})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
