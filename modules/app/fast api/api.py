from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from features.build_features import feature_builder

app = FastAPI()

model = joblib.load("rf_url_risk_model.pkl")

class URLRequest(BaseModel):
    url: str

REVERSE_LABEL_MAP = {
    2: "HIGH",
    3: "CRITICAL"
}

FEATURE_COLUMNS = [
    "is_tracker",
    "active_param_count",
    "analytics_param_count",
    "technical_param_count",
    "unknown_param_count",
    "parameter_risk_score"
]

@app.post("/predict")
def predict_url_risk(request: URLRequest):
    url = request.url

    features_df = feature_builder(url)

    X = features_df[FEATURE_COLUMNS]

    pred_class = model.predict(X)[0]
    pred_probs = model.predict_proba(X)[0]
    confidence = float(max(pred_probs))

    return {
        "url": url,
        "predicted_risk": REVERSE_LABEL_MAP.get(pred_class, "UNKNOWN"),
        "confidence": round(confidence, 3)
    }
