import pandas as pd
import joblib
from db.db import get_db,save_prediction
import features.store_url_features as store_url_features
import logging

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

store_url_features.store_url_feature()

conn = get_db()
query = """
SELECT
    url,
    is_tracker,
    active_param_count,
    analytics_param_count,
    technical_param_count,
    unknown_param_count,
    parameter_risk_score,
    parameter_risk_label
FROM url_features;
"""
df = pd.read_sql(query, conn)
conn.close()

logging.info(f"Total rows loaded: {len(df)}")

df = df.dropna(subset=["parameter_risk_label"])

df = df[df["parameter_risk_score"] >= 7]

logging.info(f"Risky URLs used for ML: {len(df)}")

def explain(row):
    reasons = []

    if row["is_tracker"]:
        reasons.append("Known tracking domain")

    if row["active_param_count"] > 0:
        reasons.append("Active tracking parameters")

    if row["technical_param_count"] > 0:
        reasons.append("Technical/session parameters")

    if row["parameter_risk_score"] >= 8:
        reasons.append("Sensitive token-like values")

    return ", ".join(reasons)

FEATURE_COLUMNS = [
    "is_tracker",
    "active_param_count",
    "analytics_param_count",
    "technical_param_count",
    "unknown_param_count",
    "parameter_risk_score"
]

X = df[FEATURE_COLUMNS]

label_map = {
    "HIGH": 2,
    "CRITICAL": 3
}

y = df["parameter_risk_label"].map(label_map)

logging.info("\nLabel distribution:")
logging.info(str(y.value_counts()))

urls=df["url"]
X_train, X_test, y_train, y_test,url_train,url_test= train_test_split(
    X,
    y,
    urls,
    test_size=0.25,
    random_state=42,
    stratify=y
)

rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=14,
    min_samples_split=4,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)
y_prob = rf.predict_proba(X_test)
confidence = y_prob.max(axis=1)

results=X_test.copy()
results['url']=url_test.values
results['true_label']=y_test.values
results['predicted_label']=y_pred
results['confidence']=confidence.clip(0.55,0.99)

reverse_label_map={v:k for k,v in label_map.items()}
results['true_label']=results['true_label'].map(reverse_label_map)
results['predicted_label']=results['predicted_label'].map(reverse_label_map)

def verdict(row):
    if row["predicted_label"] == "CRITICAL" and row["confidence"] > 0.9:
        return "Immediate Attention Required"
    elif row["predicted_label"] == "HIGH":
        return "Potential Privacy Risk"
    else:
        return "Monitor"

results["verdict"] = results.apply(verdict, axis=1)
results['explanation']=results.apply(explain,axis=1)

logging.info("\nClassification Report:\n")
logging.info(classification_report(
    y_test,
    y_pred,
    labels=[2, 3],
    target_names=["HIGH", "CRITICAL"]
))

logging.info("\nConfusion Matrix:\n")
logging.info(str(confusion_matrix(y_test, y_pred,labels=[2, 3] )))


logging.info("\nFeature Importances:")
for name, score in zip(FEATURE_COLUMNS, rf.feature_importances_):
    logging.info(f"{name:25s} : {score:.4f}")

logging.info("\nTop Risky URLs:")
logging.info(str(results[['url','predicted_label','confidence','verdict','explanation']].sort_values(
    by=['predicted_label','confidence'],
    ascending=False
).head(10)))

for _, row in results.iterrows():
    save_prediction(
        row['url'],
        row['predicted_label'],
        float(row['confidence']),
        row['verdict']
    )


joblib.dump(rf, "rf_url_risk_model.pkl")
logging.info("\n Model saved as rf_url_risk_model.pkl")
