
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data" / "processed"
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"
LABEL = "label"

def main():
    start = time.time()

    print("=" * 65)
    print("CICIoT2023 MULTI-CLASS MODEL TRAINING")
    print("=" * 65)

    print("\n[1/5] Loading training data...")
    train_df = pd.read_csv(TRAIN_FILE)
    print("Training shape:", train_df.shape)

    print("\n[2/5] Loading test data...")
    test_df = pd.read_csv(TEST_FILE)
    print("Testing shape:", test_df.shape)

    if LABEL not in train_df.columns or LABEL not in test_df.columns:
        raise ValueError("Expected a 'label' column in both CSV files.")

    feature_cols = [c for c in train_df.columns if c != LABEL]

    if feature_cols != [c for c in test_df.columns if c != LABEL]:
        raise ValueError("Training and testing feature columns do not match.")

    X_train = train_df[feature_cols]
    y_train = train_df[LABEL]
    X_test = test_df[feature_cols]
    y_test = test_df[LABEL]

    print("Number of features:", len(feature_cols))
    print("Training samples:", len(X_train))
    print("Testing samples:", len(X_test))
    print("\nTraining class distribution:")
    print(y_train.value_counts().to_string())

    print("\n[3/5] Training Random Forest...")
    print("This may take some time. Please keep the terminal open.")

    model = RandomForestClassifier(
        n_estimators=80,
        max_depth=18,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    print("Training completed.")

    print("\n[4/5] Evaluating on the held-out test set...")
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    balanced_acc = balanced_accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, average="macro", zero_division=0
    )
    recall = recall_score(
        y_test, predictions, average="macro", zero_division=0
    )
    macro_f1 = f1_score(
        y_test, predictions, average="macro", zero_division=0
    )

    print("\n" + "=" * 65)
    print("CICIoT2023 TEST RESULTS")
    print("=" * 65)
    print(f"Accuracy:          {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"Balanced accuracy: {balanced_acc:.4f}")
    print(f"Macro precision:   {precision:.4f}")
    print(f"Macro recall:      {recall:.4f}")
    print(f"Macro F1-score:    {macro_f1:.4f}")

    report = classification_report(
        y_test, predictions, zero_division=0
    )
    print("\nClassification report:\n")
    print(report)

    labels = sorted(set(y_test.unique()) | set(pd.Series(predictions).unique()))
    matrix = confusion_matrix(y_test, predictions, labels=labels)

    pd.DataFrame(
        matrix,
        index=[f"actual_{label}" for label in labels],
        columns=[f"predicted_{label}" for label in labels],
    ).to_csv(MODEL_DIR / "confusion_matrix.csv")

    (MODEL_DIR / "classification_report.txt").write_text(
        report, encoding="utf-8"
    )

    results = {
        "dataset": "CICIoT2023",
        "model": "RandomForestClassifier",
        "test_accuracy": float(accuracy),
        "balanced_accuracy": float(balanced_acc),
        "macro_precision": float(precision),
        "macro_recall": float(recall),
        "macro_f1": float(macro_f1),
        "n_features": len(feature_cols),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "random_state": 42,
        "n_estimators": 80,
        "max_depth": 18,
        "labels": [str(label) for label in labels],
        "feature_columns": feature_cols,
    }

    (MODEL_DIR / "evaluation_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    print("\n[5/5] Saving the CICIoT2023 model...")
    joblib.dump(
        {"model": model, "feature_columns": feature_cols},
        MODEL_DIR / "ciciot_random_forest.pkl",
        compress=3,
    )

    print("\nSaved files in:", MODEL_DIR)
    print("- ciciot_random_forest.pkl")
    print("- evaluation_results.json")
    print("- classification_report.txt")
    print("- confusion_matrix.csv")
    print(f"\nTotal time: {(time.time() - start) / 60:.2f} minutes")
    print("\nCICIoT2023 training and evaluation finished.")

if __name__ == "__main__":
    main()
