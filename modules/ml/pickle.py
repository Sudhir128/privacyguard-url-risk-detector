import joblib
import pandas as pd
import logging

model = joblib.load("rf_url_risk_model.pkl")

dummy = pd.DataFrame([{
    "is_tracker": 1,
    "active_param_count": 2,
    "analytics_param_count": 1,
    "technical_param_count": 1,
    "unknown_param_count": 0,
    "parameter_risk_score": 9
}])

reverse_label_map = {2: "HIGH", 3: "CRITICAL"}

pred = model.predict(dummy)[0]
proba = model.predict_proba(dummy)[0]

logging.info(f"Predicted Risk: {reverse_label_map[pred]}")
logging.info(f"Confidence: {max(proba)*100:.2f}%")
