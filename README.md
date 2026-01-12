# ePhishient AI - Phishing URL Detector

ePhishient AI is a machine learning-powered web application designed to detect phishing URLs in real-time. It analyzes the lexical structure of a URL to determine the likelihood of it being malicious, providing users with a confidence score and detailed breakdown of risk factors.

## 🚀 Features

-   **Real-time Analysis**: Instantly checks URLs against a trained Random Forest model.
-   **Lexical Feature Extraction**: Analyzes over 20 distinct features (entropy, special characters, length, etc.) without needing to visit the site content.
-   **Live Model Retraining**: Allows administrators to trigger a model retrain directly from the UI using the latest threat intelligence feeds.
-   **Responsive UI**: Mobile-friendly design with Dark Mode support.
-   **Reporting**: Export analysis results to PDF or copy to clipboard.
-   **Live Data Sources**: Fetches training data dynamically from PhishTank, OpenPhish, URLhaus, and Tranco.

## 🛠️ Technical Architecture

The project is built using **Python (Flask)** for the backend and **HTML/CSS/JavaScript** for the frontend.

### 1. Data Collection (`data_loader.py`)
The system automatically aggregates data from multiple sources to build a balanced dataset:
-   **Malicious Sources**:
    -   **PhishTank**: Online valid phishing URLs.
    -   **OpenPhish**: Feed of known phishing sites.
    -   **URLhaus**: Recent malware URL distribution sites.
-   **Benign Sources**:
    -   **Tranco List**: Top 1 Million popular domains (uses top 3,000 for training).
-   **Balancing**: The loader ensures an equal distribution of malicious and benign URLs to prevent model bias.

### 2. Feature Engineering (`train_model.py`)
Instead of relying on blacklists, the model analyzes the *structure* of the URL. The `PhishingDetector` class extracts 20 features, including:
-   **Structural**: URL length, hostname length, path length, TLD length.
-   **Statistical**: Counts of special characters (`-`, `@`, `?`, `%`, `.`, `=`, `&`, `_`).
-   **Entropy**: Calculates the randomness of the URL string (high entropy often indicates algorithmic generation).
-   **Indicators**: Checks for IP addresses in hostnames, use of URL shorteners, and sensitive keywords (e.g., "login", "secure").

### 3. Machine Learning Model
-   **Algorithm**: Random Forest Classifier (`sklearn.ensemble.RandomForestClassifier`).
-   **Training**: The model is trained on the processed feature set.
-   **Persistence**: The trained model is saved as `phishing_model.pkl` for quick inference.

### 4. Web Application (`app.py`)
-   **Framework**: Flask.
-   **Routes**:
    -   `/`: Renders the main interface.
    -   `/predict`: Accepts a URL, validates reachability, extracts features, and returns the prediction/confidence score.
    -   `/retrain`: Triggers the data loading and training pipeline in the background.

### 5. Frontend (`templates/index.html` & `static/`)
-   **Interaction**: Users input URLs, which are sent via AJAX (`fetch`) to the backend.
-   **Visualization**: Displays a risk meter, confidence percentage, and a list of specific reasons for the diagnosis.
-   **Utilities**: Includes theme toggling, clipboard copying, and PDF generation using `jspdf`.

## 📂 Project Structure

```text
phishing_ml/
├── app.py                 # Main Flask application entry point
├── data_loader.py         # Script to fetch and prepare training data
├── train_model.py         # ML model definition and feature extraction logic
├── phishing_model.pkl     # Serialized trained model (generated after training)
├── top-1m.csv             # (Optional) Local copy of benign domains
├── templates/
│   └── index.html         # Main web interface
└── static/
    ├── style.css          # Styling (Dark mode, responsive layout)
    └── script.js          # Frontend logic (API calls, UI updates, Modals)
```

## ⚙️ Installation & Setup

### Prerequisites
-   Python 3.8+
-   pip (Python Package Manager)

### Steps

1.  **Install Dependencies**:
    ```bash
    pip install flask pandas numpy scikit-learn requests joblib
    ```

2.  **Initial Training**:
    Before running the app, generate the model file:
    ```bash
    python train_model.py
    ```
    *Note: This will download data from the internet. If you have a local `top-1m.csv`, place it in the root directory to speed this up.*

3.  **Run the Application**:
    ```bash
    python app.py
    ```

4.  **Access**:
    Open your browser and navigate to `http://localhost:5000`.

## 🔍 Usage

1.  **Analyze**: Enter a URL (e.g., `http://google.com` or a suspicious link) and press Enter or click "Analyze".
2.  **Review**: Check the "Safe" or "Warning" status, confidence score, and specific risk factors (e.g., "Hostname is an IP address").
3.  **Share**: Click "Share Result" to copy the report or download it as a PDF.
4.  **Retrain**: If the model feels outdated, click "Retrain AI Model" at the bottom to fetch fresh data and update the logic.

## 🛡️ Security Note

This tool analyzes URL strings and attempts to ping the server to verify reachability. It does **not** download page content or execute scripts from the target URL, making it safe to use for scanning potential threats.

---
*Powered by Flask & Scikit-Learn*