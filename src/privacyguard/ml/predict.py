import logging
import threading

import joblib
import pandas as pd

from privacyguard.config import get_settings
from privacyguard.core.risk_engine import assign_score
from privacyguard.features.builder import FEATURE_COLUMNS, build_features
from privacyguard.ml.train import REVERSE_LABEL_MAP, train_model

logger = logging.getLogger(__name__)

_model_lock = threading.Lock()
_cached_model = None
_cached_metadata = None


def _load_or_train():
    """Loads the bundled model, training it on the fly if this is a first run
    and no model file exists yet on disk."""
    global _cached_model, _cached_metadata

    if _cached_model is not None:
        return _cached_model, _cached_metadata

    with _model_lock:
        if _cached_model is not None:
            return _cached_model, _cached_metadata

        settings = get_settings()
        model_file = settings.model_file

        if not model_file.exists():
            logger.info("No model found at %s — training a fresh one now.", model_file)
            train_model(output_path=model_file)

        bundle = joblib.load(model_file)
        _cached_model = bundle["model"]
        _cached_metadata = bundle.get("metadata", {})
        return _cached_model, _cached_metadata


def reload_model() -> None:
    """Drop the cached model so the next prediction reloads it from disk."""
    global _cached_model, _cached_metadata
    with _model_lock:
        _cached_model = None
        _cached_metadata = None


def _verdict(predicted_label: str, confidence: float) -> str:
    if predicted_label == "CRITICAL" and confidence > 0.9:
        return "Immediate Attention Required"
    if predicted_label in ("HIGH", "CRITICAL"):
        return "Potential Privacy Risk"
    return "Monitor"


def model_status() -> dict:
    model, metadata = _load_or_train()
    return {"loaded": model is not None, **metadata}


def predict_url(url: str) -> dict:
    model, _ = _load_or_train()

    features = build_features(url)
    X = pd.DataFrame([features])[FEATURE_COLUMNS]

    pred_class = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0]
    confidence = round(float(max(proba)), 3)
    predicted_label = REVERSE_LABEL_MAP.get(pred_class, "UNKNOWN")

    risk = assign_score(url)

    return {
        "url": url,
        "predicted_label": predicted_label,
        "confidence": confidence,
        "verdict": _verdict(predicted_label, confidence),
        "risk_score": risk["score"],
        "risk_label": risk["risk_label"],
        "is_tracker": bool(features["is_tracker"]),
        "is_phishing": risk["is_phishing"],
        "matched_brand": risk["matched_brand"],
        "explanation": risk["reasons"],
        "features": features,
    }


def predict_batch(urls: list[str]) -> list[dict]:
    return [predict_url(url) for url in urls]
