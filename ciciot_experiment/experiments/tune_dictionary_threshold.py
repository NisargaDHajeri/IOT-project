
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data" / "processed"
OUT = BASE / "experiments" / "dictionary_threshold_v1"
OUT.mkdir(parents=True, exist_ok=True)

TARGET = "DictionaryBruteForce"
LABEL = "label"
SEED = 42


def evaluate(y_true, predictions, title):
    precision = precision_score(
        y_true, predictions, labels=[TARGET],
        average=None, zero_division=0
    )[0]
    recall = recall_score(
        y_true, predictions, labels=[TARGET],
        average=None, zero_division=0
    )[0]
    f1 = f1_score(
        y_true, predictions, labels=[TARGET],
        average=None, zero_division=0
    )[0]

    print(f"\n--- {title} ---")
    print(f"Accuracy: {accuracy_score(y_true, predictions):.4f}")
    print(f"{TARGET} precision: {precision:.4f}")
    print(f"{TARGET} recall:    {recall:.4f}")
    print(f"{TARGET} F1-score:   {f1:.4f}")

    return {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "dictionary_precision": float(precision),
        "dictionary_recall": float(recall),
        "dictionary_f1": float(f1),
    }


def apply_threshold(probabilities, classes, threshold):
    target_index = list(classes).index(TARGET)
    best_indices = probabilities.argmax(axis=1)
    target_mask = probabilities[:, target_index] >= threshold

    # Assign the target class only when its probability passes
    # the tuned threshold; otherwise retain the strongest alternative.
    best_indices[target_mask] = target_index
    return classes[best_indices]


def main():
    start = time.time()
    print("Loading CICIoT2023 training data...")
    train_df = pd.read_csv(DATA / "train.csv")
    test_df = pd.read_csv(DATA / "test.csv")

    feature_cols = [c for c in train_df.columns if c != LABEL]
    X = train_df[feature_cols]
    y = train_df[LABEL]
    X_test = test_df[feature_cols]
    y_test = test_df[LABEL]

    if TARGET not in set(y):
        raise ValueError(f"Target class {TARGET} not found.")

    # The held-out test set is not used to choose the threshold.
    X_fit, X_val, y_fit, y_val = train_test_split(
        X, y, test_size=0.20, random_state=SEED, stratify=y
    )

    print("Fit samples:", len(X_fit))
    print("Validation samples:", len(X_val))
    print("Held-out test samples:", len(X_test))
    print("\nTraining experimental Random Forest...")

    model = RandomForestClassifier(
        n_estimators=80,
        max_depth=18,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=SEED,
        n_jobs=-1,
    )
    model.fit(X_fit, y_fit)

    print("Getting validation probabilities...")
    val_prob = model.predict_proba(X_val)
    classes = model.classes_
    default_pred = classes[val_prob.argmax(axis=1)]

    baseline = evaluate(y_val, default_pred, "Validation baseline")

    target_index = list(classes).index(TARGET)
    target_scores = val_prob[:, target_index]
    actual_target = (y_val.to_numpy() == TARGET)

    # Try a range of thresholds, using validation data only.
    rows = []
    for threshold in np.arange(0.10, 0.96, 0.025):
        pred = apply_threshold(val_prob, classes, float(threshold))
        stats = evaluate_silent(actual_target, pred == TARGET)
        rows.append({
            "threshold": round(float(threshold), 3),
            **stats,
        })

    results = pd.DataFrame(rows)
    results.to_csv(OUT / "validation_thresholds.csv", index=False)

    # Prefer the best F1 among thresholds reaching at least 30%
    # precision on validation. If none qualify, use best F1 overall.
    eligible = results[results["precision"] >= 0.30]
    if eligible.empty:
        chosen = results.loc[results["f1"].idxmax()]
        reason = "No threshold reached 30% validation precision; selected best F1."
    else:
        chosen = eligible.loc[eligible["f1"].idxmax()]
        reason = "Highest validation F1 among thresholds with precision >= 30%."

    threshold = float(chosen["threshold"])
    print("\nChosen validation threshold:", threshold)
    print("Selection rule:", reason)
    print("Validation precision:", round(float(chosen["precision"]), 4))
    print("Validation recall:", round(float(chosen["recall"]), 4))
    print("Validation F1:", round(float(chosen["f1"]), 4))

    # Final evaluation is performed once on the held-out test set.
    print("\nEvaluating the selected threshold on held-out test data...")
    test_prob = model.predict_proba(X_test)
    test_default = classes[test_prob.argmax(axis=1)]
    test_tuned = apply_threshold(test_prob, classes, threshold)

    baseline_test = evaluate(y_test, test_default, "Test baseline")
    tuned_test = evaluate(y_test, test_tuned, "Test tuned threshold")

    print("\nTuned classification report:")
    report = classification_report(
        y_test, test_tuned, zero_division=0
    )
    print(report)

    labels = sorted(set(y_test.unique()) | set(classes))
    matrix = confusion_matrix(y_test, test_tuned, labels=labels)
    pd.DataFrame(
        matrix,
        index=[f"actual_{x}" for x in labels],
        columns=[f"predicted_{x}" for x in labels],
    ).to_csv(OUT / "confusion_matrix_tuned.csv")

    (OUT / "classification_report_tuned.txt").write_text(
        report, encoding="utf-8"
    )

    joblib.dump(
        {
            "model": model,
            "feature_columns": feature_cols,
            "target_class": TARGET,
            "target_threshold": threshold,
            "classes": list(classes),
        },
        OUT / "ciciot_rf_threshold_tuned.pkl",
        compress=3,
    )

    summary = {
        "experiment": "DictionaryBruteForce threshold tuning",
        "threshold": threshold,
        "selection_rule": reason,
        "validation_baseline": baseline,
        "test_baseline": baseline_test,
        "test_tuned": tuned_test,
        "train_samples_used_for_fit": len(X_fit),
        "validation_samples": len(X_val),
        "test_samples": len(X_test),
        "features": len(feature_cols),
        "random_state": SEED,
    }
    (OUT / "results.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    print("\nSaved experiment separately to:", OUT)
    print("The original CICIoT2023 and smart-door models were not overwritten.")
    print(f"Elapsed time: {(time.time() - start) / 60:.2f} minutes")


def evaluate_silent(actual, predicted):
    return {
        "precision": float(precision_score(
            actual, predicted, zero_division=0
        )),
        "recall": float(recall_score(
            actual, predicted, zero_division=0
        )),
        "f1": float(f1_score(
            actual, predicted, zero_division=0
        )),
    }


if __name__ == "__main__":
    main()
