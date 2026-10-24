"""Random Forest Model Trainer for Door Lock Intrusion Assessment."""

import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "risk_classifier.pkl"
DATA_PATH = BASE_DIR / "data" / "risk_dataset.csv"

FEATURES = [
    "battery_level",
    "cpu_utilization",
    "memory_usage",
    "failed_auth_attempts",
    "successful_auth_attempts",
    "communication_latency_ms",
    "network_anomaly",
    "threat_indicator",
]


def train_and_save_model():
    """Trains the Random Forest model and persists it to disk."""
    if not DATA_PATH.exists():
        from ml.dataset_generator import generate_synthetic_dataset
        generate_synthetic_dataset()

    df = pd.read_csv(DATA_PATH)
    X = df[FEATURES]
    y = df["risk_level"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=250,
        max_depth=14,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
        n_jobs=1,
    )

    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    acc = accuracy_score(y_test, pred)

    print(f"Random Forest Model Trained. Test Accuracy: {acc:.4f}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    return model


if __name__ == "__main__":
    train_and_save_model()
