# privacyguard-url-risk-detector
PrivacyGuard is a machine learning–based URL privacy risk detector that analyzes URL parameters to identify tracking behavior. It predicts risk levels with confidence scores using Random Forest, PostgreSQL storage, and a FastAPI prediction service.

# Features
URL Analysis – Extracts query parameters and domain-based indicators
Machine Learning Model – Random Forest classifier for risk prediction
Confidence Scores – Probability-based confidence for each prediction
PostgreSQL Storage – Stores URL features and prediction results
FastAPI Backend – Real-time URL risk assessment via REST API
Tracker Detection – Identifies analytics, technical, and unknown parameters

---

# Tech Stack

Language: Python
ML: Scikit-learn (Random Forest)
Backend: FastAPI
Database: PostgreSQL
Data Handling: Pandas
Model Persistence: Joblib

---

# Project Architecture 
- The PrivacyGuard system follows a modular, layered architecture designed for scalability, maintainability, and real-time risk assessment.
- At the API layer, a FastAPI backend acts as the entry point. It receives URLs from clients, validates input, and returns structured risk predictions with confidence scores.
- The core analysis layer handles URL parsing and inspection. It breaks down URLs into domains and query parameters, identifies known trackers, and applies rule-based logic to support risk interpretation.
- The feature engineering layer transforms raw URL components into machine-learning–ready features, such as tracker presence, parameter counts, and risk scores.
- The machine learning layer uses a trained Random Forest classifier to predict the privacy risk level of a URL and estimate confidence probabilities.
- The database layer uses PostgreSQL to persist extracted features and prediction results, enabling auditing, analytics, and future model improvements.
- Supporting layers include tracker intelligence data, batch processing scripts, and automated tests to ensure system reliability.


---

# Machine learning 
Algorithm: Random Forest Classifier

Input Features:
- is_tracker
- active_param_count
- analytics_param_count
- technical_param_count
- unknown_param_count
- parameter_risk_score

Output:
- Risk Label (HIGH, CRITICAL)
- Confidence Score

---

# Database Design

url_features – Stores extracted URL features and risk scores
url_predictions – Stores prediction results and confidence values

---

# How to Run Locally

Clone the repository
  git clone https://github.com/your-username/privacyguard-url-risk-detector.git
  cd privacyguard-url-risk-detector

Create and activate virtual environment
  python -m venv venv
  source venv/bin/activate   # Windows: venv\Scripts\activate

Install dependencies
  pip install -r requirements.txt

Run FastAPI server
  uvicorn app.api.api:app --reload

Open Swagger UI
  http://127.0.0.1:8000/docs

---

# API Usage

Predict URL Risk
Endpoint: POST /predict
Example:
Request Body:
{
  "url": "https://example.com?utm_source=test"
}
Response:
{
  "url": "https://example.com?utm_source=test",
  "predicted_risk": "HIGH",
  "confidence": 0.982
}

---

# Use Cases

Privacy-aware URL analysis
Detecting tracking-heavy links
Security & privacy research
Educational ML + backend project

---

# Future Enhancements

Frontend UI 
Browser extension integration
Support for batch URL analysis
Upgrade to Light GBM model(ML Enhancement)
