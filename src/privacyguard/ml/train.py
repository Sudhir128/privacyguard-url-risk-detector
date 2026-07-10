"""Trains the bundled Random Forest risk classifier.

There's no labeled "ground truth" phishing/tracking dataset shipped with this
project, so the model is trained to reproduce privacyguard.core.risk_engine's
heuristic verdict from the feature vector — this turns a fast, deterministic
rule engine into a model that also yields a calibrated confidence score and
generalizes to URL patterns the rules don't literally enumerate. Real scan
history (once collected in the DB) can later replace/augment this synthetic
corpus without changing the training code.
"""

import json
import logging
import random
from datetime import datetime, timezone

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, train_test_split

from privacyguard.config import get_settings
from privacyguard.core.phishing_detector import KNOWN_BRANDS, SUSPICIOUS_TLDS
from privacyguard.core.risk_engine import assign_score
from privacyguard.core.tracker_loader import get_tracker_domains
from privacyguard.features.builder import FEATURE_COLUMNS, build_features

logger = logging.getLogger(__name__)

LABEL_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
REVERSE_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}

CLEAN_DOMAINS = [
    "wikipedia.org", "python.org", "docs.python.org", "github.com",
    "stackoverflow.com", "developer.mozilla.org", "arxiv.org", "nasa.gov",
    "nature.com", "bbc.co.uk", "reuters.com", "npr.org", "khanacademy.org",
    "coursera.org", "gutenberg.org", "archive.org", "w3.org", "gnu.org",
    "kernel.org", "readthedocs.io",
]

CLEAN_PATHS = ["/", "/about", "/docs/intro", "/search", "/en/latest/", "/wiki/Privacy", "/articles/2024"]
SAFE_QUERY = ["", "?q=weather", "?page=2", "?lang=en", "?sort=recent"]

CREDENTIAL_PARAMS = [
    "password=Summer2024!", "api_key=glpat-dummytokenfortesting",
    "pwd=hunter2", "secret=topsecretvalue123", "client_secret=cs_9f8a7b6c5d4e3f2a1b",
    "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQqqerJmNqRO1z",
    "auth=AKIAABCDEFGHIJKLMNOP",
]

PHISHING_KEYWORDS_PATHS = ["/login/verify", "/account/update", "/secure/signin", "/wallet/confirm", "/reset/password"]


def _homoglyph_variant(rng: random.Random, brand: str) -> str:
    subs = {"o": "0", "l": "1", "e": "3", "a": "4", "s": "5"}
    chars = list(brand)
    for i, ch in enumerate(chars):
        if ch in subs and rng.random() < 0.5:
            chars[i] = subs[ch]
    return "".join(chars)


def _generate_clean_urls(rng: random.Random, n: int) -> list[str]:
    urls = []
    for _ in range(n):
        domain = rng.choice(CLEAN_DOMAINS)
        path = rng.choice(CLEAN_PATHS)
        query = rng.choice(SAFE_QUERY)
        urls.append(f"https://{domain}{path}{query}")
    return urls


def _generate_tracker_urls(rng: random.Random, n: int) -> list[str]:
    tracker_domains = list(get_tracker_domains())
    if not tracker_domains:
        return []

    scheme_choices = ["https://", "https://", "http://"]  # mostly https, some plaintext
    param_sets = [
        "", "?utm_source=fb&utm_medium=cpc", "?fbclid=abc123def456",
        "?gclid=xyz789&utm_campaign=spring_sale", "?ref=partner&aff_id=42",
    ]
    urls = []
    for _ in range(n):
        domain = rng.choice(tracker_domains)
        scheme = rng.choice(scheme_choices)
        params = rng.choice(param_sets)
        urls.append(f"{scheme}{domain}/collect{params}")
    return urls


def _generate_credential_leak_urls(rng: random.Random, n: int) -> list[str]:
    domains = CLEAN_DOMAINS + ["example.com", "internal-app.io", "myservice.net"]
    urls = []
    for _ in range(n):
        domain = rng.choice(domains)
        param = rng.choice(CREDENTIAL_PARAMS)
        urls.append(f"https://{domain}/reset?{param}")
    return urls


def _generate_phishing_urls(rng: random.Random, n: int) -> list[str]:
    brands = list(KNOWN_BRANDS)
    tlds = list(SUSPICIOUS_TLDS)
    urls = []
    for _ in range(n):
        style = rng.choice(["typosquat", "ip", "subdomain_spam"])
        brand = rng.choice(brands)

        if style == "typosquat":
            variant = _homoglyph_variant(rng, brand)
            tld = rng.choice(tlds)
            path = rng.choice(PHISHING_KEYWORDS_PATHS)
            urls.append(f"http://{variant}-secure-login.{tld}{path}")
        elif style == "ip":
            ip = f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
            path = rng.choice(PHISHING_KEYWORDS_PATHS)
            urls.append(f"http://{ip}{path}")
        else:
            variant = _homoglyph_variant(rng, brand)
            tld = rng.choice(tlds)
            path = rng.choice(PHISHING_KEYWORDS_PATHS)
            urls.append(f"http://verify.account.{variant}.confirm-secure.{tld}{path}")
    return urls


def generate_training_urls(seed: int = 42, per_category: int = 150) -> list[str]:
    rng = random.Random(seed)
    urls = (
        _generate_clean_urls(rng, per_category)
        + _generate_tracker_urls(rng, per_category)
        + _generate_credential_leak_urls(rng, per_category)
        + _generate_phishing_urls(rng, per_category)
    )
    rng.shuffle(urls)
    return urls


def build_training_frame(urls: list[str]) -> pd.DataFrame:
    rows = []
    for url in urls:
        features = build_features(url)
        label = assign_score(url)["risk_label"]
        row = dict(features)
        row["url"] = url
        row["label"] = label
        rows.append(row)
    return pd.DataFrame(rows)


def train_model(output_path=None) -> dict:
    settings = get_settings()
    output_path = output_path or settings.model_file

    urls = generate_training_urls()
    df = build_training_frame(urls)

    logger.info("Training rows: %d", len(df))
    logger.info("Label distribution:\n%s", df["label"].value_counts().to_string())

    X = df[FEATURE_COLUMNS]
    y = df["label"].map(LABEL_MAP)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=14,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    present_labels = sorted(set(y_test) | set(y_pred))
    target_names = [REVERSE_LABEL_MAP[label] for label in present_labels]

    report = classification_report(
        y_test, y_pred, labels=present_labels, target_names=target_names, zero_division=0
    )
    matrix = confusion_matrix(y_test, y_pred, labels=present_labels)
    accuracy = float((y_pred == y_test).mean())

    logger.info("Classification report:\n%s", report)
    logger.info("Confusion matrix (%s):\n%s", target_names, matrix)

    feature_importance = dict(zip(FEATURE_COLUMNS, rf.feature_importances_.tolist()))
    logger.info("Feature importances: %s", json.dumps(feature_importance, indent=2))

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "accuracy": accuracy,
        "feature_columns": FEATURE_COLUMNS,
        "label_map": LABEL_MAP,
        "training_rows": len(df),
    }

    joblib.dump({"model": rf, "metadata": metadata}, output_path)
    logger.info("Model saved to %s (accuracy=%.3f)", output_path, accuracy)

    return metadata


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    train_model()
