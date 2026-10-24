"""
CICIoT2023 Preprocessing Pipeline
===================================
Produces clean, split, scaled feature matrices ready for model training.

CLASSIFICATION TARGET — six traffic classes derived from filenames:
  1. BenignTraffic
  2. DictionaryBruteForce
  3. DNS_Spoofing
  4. MITM_ArpSpoofing
  5. DDoS_SYN_Flood
  6. DoS_SYN_Flood

IMPORTANT: These are NETWORK TRAFFIC ATTACK CATEGORIES, not risk tiers.
  The labels LOW / MEDIUM / HIGH belong to the separate door-lock risk
  classifier in backend/ml/ and have NO relationship to this dataset.

Directory layout (all outputs go under ciciot_experiment/):
  ciciot_experiment/
    data/
      raw/          <- source CSVs (READ ONLY -- never touched here)
      processed/    <- outputs: train.csv, test.csv, scaler.pkl, meta.json

Isolation guarantee:
  This script operates exclusively within ciciot_experiment/.
  It does NOT import from, write to, or modify anything under backend/.
  It does NOT train any model.

Run from the project root:
  python ciciot_experiment/preprocess.py
"""

import os
import sys
import time
import warnings
import json
import numpy as np
import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

warnings.filterwarnings("ignore", category=pd.errors.PerformanceWarning)

# -- Path constants ------------------------------------------------------------
SCRIPT_DIR    = Path(__file__).resolve().parent          # ciciot_experiment/
RAW_DIR       = SCRIPT_DIR / "data" / "raw"
PROCESSED_DIR = SCRIPT_DIR / "data" / "processed"

# -- Filename -> label mapping (verified in ciciot_verification_report.md) ----
# Six classes for a MULTICLASS TRAFFIC CLASSIFICATION problem.
# Labels are derived solely from filenames -- no label column exists in the CSVs.
# These class strings are NOT LOW/MEDIUM/HIGH risk tiers.
FILE_LABEL_MAP = {
    "BenignTraffic.pcap.csv":        "BenignTraffic",         # class 0
    "DictionaryBruteForce.pcap.csv": "DictionaryBruteForce",  # class 1
    "DNS_Spoofing.pcap.csv":         "DNS_Spoofing",          # class 2
    "MITM-ArpSpoofing.pcap.csv":     "MITM_ArpSpoofing",      # class 3
    "DDoS-SYN_Flood.pcap.csv":       "DDoS_SYN_Flood",        # class 4
    "DoS-SYN_Flood.pcap.csv":        "DoS_SYN_Flood",         # class 5
}
N_CLASSES = len(FILE_LABEL_MAP)  # must equal 6

# -- Feature columns (all 39; verified identical across all six files) ---------
FEATURE_COLS = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
    "IAT", "Number", "Variance",
]
LABEL_COL    = "label"
RANDOM_STATE = 42

# -- Audit log -----------------------------------------------------------------
audit = []


def log(msg: str) -> None:
    timestamp = time.strftime("%H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    audit.append(line)


# =============================================================================
# STEP 0 -- Safety checks (read-only)
# =============================================================================
def check_raw_files() -> dict:
    log("STEP 0 -- Verifying raw CSV files (read-only check)")
    source_sizes = {}
    for fname in FILE_LABEL_MAP:
        path = RAW_DIR / fname
        if not path.exists():
            log(f"  ERROR: Missing file: {path}")
            sys.exit(1)
        source_sizes[fname] = path.stat().st_size
        log(f"  OK  {fname}  ({source_sizes[fname] / 1e6:.1f} MB)")
    log("  All 6 source files confirmed present.")
    return source_sizes


# =============================================================================
# STEP 1 -- Load and label
# =============================================================================
def load_and_label() -> pd.DataFrame:
    log("\nSTEP 1 -- Loading CSVs and assigning labels from filenames")
    frames = []
    for fname, label in FILE_LABEL_MAP.items():
        path = RAW_DIR / fname
        df = pd.read_csv(path, low_memory=False)
        df[LABEL_COL] = label
        log(f"  Loaded {fname:<40}  {len(df):>8,} rows  label='{label}'")
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    log(f"  Combined: {len(combined):,} rows x {len(combined.columns)} columns")

    missing_cols = [c for c in FEATURE_COLS if c not in combined.columns]
    if missing_cols:
        log(f"  ERROR: Missing expected feature columns: {missing_cols}")
        sys.exit(1)
    log(f"  All {len(FEATURE_COLS)} expected feature columns present.")
    return combined


# =============================================================================
# STEP 2 -- Remove conflicting feature vectors and same-label duplicates
# =============================================================================
def remove_conflicts_and_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    log("\nSTEP 2 -- Removing conflicting feature vectors and duplicates")

    # Hashing narrows exact comparisons to vectors whose hashes appear
    # under multiple labels; exact grouping resolves hash collisions.
    feature_hashes = pd.util.hash_pandas_object(
        df[FEATURE_COLS], index=False
    )
    labels_per_hash = df[LABEL_COL].groupby(
        feature_hashes.to_numpy(), sort=False
    ).nunique()
    candidate_hashes = labels_per_hash.index[labels_per_hash > 1]

    conflict_mask = np.zeros(len(df), dtype=bool)
    conflict_vectors = 0
    if len(candidate_hashes):
        candidate_positions = np.flatnonzero(
            feature_hashes.isin(candidate_hashes).to_numpy()
        )
        candidates = df.iloc[candidate_positions]
        labels_per_vector = candidates.groupby(
            FEATURE_COLS, sort=False, dropna=False
        )[LABEL_COL].transform("nunique")
        conflicting = labels_per_vector.to_numpy() > 1
        conflict_mask[candidate_positions] = conflicting
        conflict_vectors = candidates.loc[
            conflicting, FEATURE_COLS
        ].drop_duplicates().shape[0]

    affected_rows = int(conflict_mask.sum())
    log(
        f"  Conflicting feature vectors: {conflict_vectors:,}  |  "
        f"Affected rows: {affected_rows:,}"
    )
    df = df.loc[~conflict_mask].copy()

    before = len(df)
    df = df.drop_duplicates(subset=FEATURE_COLS + [LABEL_COL])
    dropped = before - len(df)
    log(
        f"  Same-label duplicates removed: {dropped:,}  |  "
        f"Rows retained: {len(df):,}"
    )
    log(f"  Class distribution after dedup:")
    for label, count in df[LABEL_COL].value_counts().items():
        log(f"    {label:<30}  {count:>8,}  ({100*count/len(df):.2f}%)")
    return df.reset_index(drop=True)


# =============================================================================
# STEP 4 -- Impute Rate using training-only per-class medians
# =============================================================================
def impute_rate_train_only(
    train_df: pd.DataFrame, test_df: pd.DataFrame
):
    log("\nSTEP 4 -- Imputing Rate from training-only per-class medians")
    train_df = train_df.copy()
    test_df = test_df.copy()

    for partition in (train_df, test_df):
        partition["Rate"] = pd.to_numeric(
            partition["Rate"], errors="raise"
        ).replace([np.inf, -np.inf], np.nan)

    medians = {}
    for cls in FILE_LABEL_MAP.values():
        finite_rates = train_df.loc[
            train_df[LABEL_COL] == cls, "Rate"
        ].dropna()
        if finite_rates.empty:
            raise ValueError(
                f"Cannot impute Rate for class '{cls}': "
                "the training partition has no finite Rate values."
            )

        median = float(finite_rates.median())
        if not np.isfinite(median):
            raise ValueError(
                f"Cannot impute Rate for class '{cls}': "
                "its training median is not finite."
            )
        medians[cls] = median
        log(f"  {cls:<30} training median: {median:.6f}")

    for name, partition in (("TRAIN", train_df), ("TEST", test_df)):
        for cls, median in medians.items():
            mask = (partition[LABEL_COL] == cls) & partition["Rate"].isna()
            filled = int(mask.sum())
            if filled:
                partition.loc[mask, "Rate"] = median
                log(f"  {name}: filled {filled:,} Rate values for '{cls}'")

    return train_df, test_df


# =============================================================================
# STEP 5 -- Impute NaN in 'Std' and 'Variance' with 0.0
# =============================================================================
def impute_nan_std_variance(
    df: pd.DataFrame, partition_name: str
) -> pd.DataFrame:
    log(
        f"\nSTEP 5 -- Imputing NaN in 'Std' and 'Variance' with 0.0 "
        f"({partition_name})"
    )
    log("  (Single-packet flows have undefined std/variance -> 0.0 is correct)")
    for col in ["Std", "Variance"]:
        n_nan = int(df[col].isna().sum())
        if n_nan > 0:
            df[col] = df[col].fillna(0.0)
            log(f"  '{col}': filled {n_nan} NaN -> 0.0")
        else:
            log(f"  '{col}': 0 NaN -- no action needed.")
    return df


# =============================================================================
# STEP 6 -- Data quality assertion
# =============================================================================
def assert_clean(df: pd.DataFrame, partition_name: str) -> None:
    log(
        f"\nSTEP 6 -- Data quality assertion for {partition_name} "
        "(must be zero NaN and zero Inf)"
    )
    X = df[FEATURE_COLS]
    total_nan = int(X.isna().sum().sum())
    total_inf = int(np.isinf(X.select_dtypes(include=[np.number])).sum().sum())

    if total_nan > 0:
        nan_by_col = X.isna().sum()
        log(f"  FAIL: {total_nan} NaN cells remain: {nan_by_col[nan_by_col > 0].to_dict()}")
    else:
        log(f"  PASS: 0 NaN cells.")

    if total_inf > 0:
        log(f"  FAIL: {total_inf} Inf cells remain.")
    else:
        log(f"  PASS: 0 Inf cells.")

    assert total_nan == 0 and total_inf == 0, (
        f"Data still has NaN ({total_nan}) or Inf ({total_inf}) -- aborting."
    )
    log(f"  All assertions passed. Clean shape: {X.shape}")


# =============================================================================
# STEP 3 -- Stratified 80/20 train/test split
# =============================================================================
# GROUP-AWARE SPLIT LIMITATION
# ---------------------------------------------------------------------------
# A group-aware split (e.g. GroupShuffleSplit) would require a session,
# capture-file, or flow-group identifier column so that all rows from the
# same capture session are kept together in one partition. This prevents
# correlated rows in the same capture from appearing in both train and test.
#
# The 39 feature columns in these CICIoT2023 CSVs are ALL statistical
# aggregates (flow-level statistics). No capture ID, session ID, timestamp,
# or flow-group identifier column is present in any of the six files.
# Therefore group-aware splitting is NOT possible with this data.
#
# Limitation of the stratified random split used here:
#   - Rows from the same underlying capture session may appear in both
#     train and test partitions.
#   - For highly repetitive flood traffic (DDoS, DoS), near-identical but
#     non-exact rows may still appear on both sides of the split.
#   - This is the standard practice in CICIoT2023 literature given the
#     absence of session identifiers in the preprocessed CSV format.
# ---------------------------------------------------------------------------
def split(df: pd.DataFrame):
    log("\nSTEP 3 -- Stratified 80/20 train/test split")
    expected_classes = set(FILE_LABEL_MAP.values())
    class_counts = df[LABEL_COL].value_counts()
    missing_classes = expected_classes - set(class_counts.index)
    small_classes = class_counts[class_counts < 2].index.tolist()
    test_rows = int(np.ceil(len(df) * 0.20))
    train_rows = len(df) - test_rows
    if (
        missing_classes
        or small_classes
        or test_rows < len(expected_classes)
        or train_rows < len(expected_classes)
    ):
        raise ValueError(
            "Cannot create stratified train/test partitions: "
            f"missing classes={sorted(missing_classes)}, "
            f"classes with fewer than 2 rows={small_classes}, "
            f"train rows={train_rows}, test rows={test_rows}, "
            f"expected classes={len(expected_classes)}."
        )

    train_df, test_df = train_test_split(
        df,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=df[LABEL_COL],
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    n_total = len(train_df) + len(test_df)
    log(f"  Train: {len(train_df):,} rows ({100*len(train_df)/n_total:.1f}%)")
    log(f"  Test : {len(test_df):,} rows ({100*len(test_df)/n_total:.1f}%)")

    log(f"\n  Class distribution in TRAIN:")
    for cls, cnt in train_df[LABEL_COL].value_counts().items():
        log(f"    {cls:<30}  {cnt:>8,}  ({100*cnt/len(train_df):.2f}%)")

    log(f"\n  Class distribution in TEST:")
    for cls, cnt in test_df[LABEL_COL].value_counts().items():
        log(f"    {cls:<30}  {cnt:>8,}  ({100*cnt/len(test_df):.2f}%)")

    return train_df, test_df


# =============================================================================
# STEP 7 -- Fit RobustScaler on train only, transform both
# =============================================================================
def scale(X_train: np.ndarray, X_test: np.ndarray):
    log("\nSTEP 7 -- Fitting RobustScaler on TRAIN only, transforming both sets")
    log("  (RobustScaler uses median+IQR -- robust to Rate/IAT/Variance outliers)")
    scaler = RobustScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)
    log(f"  Center (median) range: [{scaler.center_.min():.4f}, {scaler.center_.max():.4f}]")
    log(f"  Scale  (IQR)  range : [{scaler.scale_.min():.4f}, {scaler.scale_.max():.4f}]")
    log("  Scaler fitted on training data ONLY -- no test-set leakage.")
    return X_train_s, X_test_s, scaler


def verify_outputs(
    X_train: np.ndarray,
    X_test: np.ndarray,
    X_train_s: np.ndarray,
    X_test_s: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    source_sizes: dict,
) -> None:
    log("\nSTEP 8 -- Verifying scaled outputs and source CSVs")
    expected_classes = set(FILE_LABEL_MAP.values())

    for name, features, labels in (
        ("TRAIN", X_train_s, y_train),
        ("TEST", X_test_s, y_test),
    ):
        if features.ndim != 2 or features.shape[1] != len(FEATURE_COLS):
            raise ValueError(
                f"{name} features have unexpected shape {features.shape}."
            )
        if not np.isfinite(features).all():
            raise ValueError(f"{name} scaled features contain NaN or Inf.")

        actual_classes = set(np.asarray(labels).tolist())
        invalid = actual_classes - expected_classes
        missing = expected_classes - actual_classes
        if invalid or missing:
            raise ValueError(
                f"{name} labels are invalid: "
                f"unexpected={sorted(invalid)}, missing={sorted(missing)}."
            )
        if len(features) != len(labels):
            raise ValueError(f"{name} feature and label row counts differ.")
        log(f"  {name}: finite features and all expected labels verified.")

    train_hashes = pd.util.hash_pandas_object(
        pd.DataFrame(X_train), index=False
    ).to_numpy()
    test_hashes = pd.util.hash_pandas_object(
        pd.DataFrame(X_test), index=False
    ).to_numpy()
    common_hashes = np.intersect1d(train_hashes, test_hashes)
    if common_hashes.size:
        test_positions = np.flatnonzero(np.isin(test_hashes, common_hashes))
        test_rows_by_hash = {}
        for position in test_positions:
            key = tuple(X_test[position].tolist())
            test_rows_by_hash.setdefault(test_hashes[position], set()).add(key)

        train_positions = np.flatnonzero(np.isin(train_hashes, common_hashes))
        for position in train_positions:
            key = tuple(X_train[position].tolist())
            if key in test_rows_by_hash.get(train_hashes[position], set()):
                raise ValueError(
                    "Exact feature-row overlap detected between train and test."
                )
    log("  No exact train/test feature-row overlap found.")

    for fname, original_size in source_sizes.items():
        path = RAW_DIR / fname
        if not path.exists() or path.stat().st_size != original_size:
            raise RuntimeError(
                f"Source CSV changed during preprocessing: {path}"
            )
    log("  All source CSV file sizes are unchanged.")


# =============================================================================
# STEP 9 -- Save all outputs to ciciot_experiment/data/processed/
# =============================================================================
def save_outputs(
    X_train_s: np.ndarray,
    X_test_s: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    scaler: RobustScaler,
) -> None:
    log("\nSTEP 9 -- Saving outputs to ciciot_experiment/data/processed/")
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    train_df = pd.DataFrame(X_train_s, columns=FEATURE_COLS)
    train_df.insert(0, LABEL_COL, y_train)
    test_df  = pd.DataFrame(X_test_s,  columns=FEATURE_COLS)
    test_df.insert(0, LABEL_COL, y_test)

    train_path  = PROCESSED_DIR / "train.csv"
    test_path   = PROCESSED_DIR / "test.csv"
    scaler_path = PROCESSED_DIR / "robust_scaler.pkl"
    meta_path   = PROCESSED_DIR / "preprocessing_meta.json"

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    joblib.dump(scaler, scaler_path)

    meta = {
        "feature_cols":             FEATURE_COLS,
        "label_col":                LABEL_COL,
        "label_map":                FILE_LABEL_MAP,
        "random_state":             RANDOM_STATE,
        "test_size":                0.20,
        "scaler":                   "RobustScaler",
        "train_rows":               int(len(train_df)),
        "test_rows":                int(len(test_df)),
        "class_distribution_train": train_df[LABEL_COL].value_counts().to_dict(),
        "class_distribution_test":  test_df[LABEL_COL].value_counts().to_dict(),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    log(f"  train.csv               -> {train_path}  ({len(train_df):,} rows)")
    log(f"  test.csv                -> {test_path}  ({len(test_df):,} rows)")
    log(f"  robust_scaler.pkl       -> {scaler_path}")
    log(f"  preprocessing_meta.json -> {meta_path}")


# =============================================================================
# MAIN
# =============================================================================
def main() -> None:
    log("=" * 70)
    log("CICIoT2023 PREPROCESSING PIPELINE")
    log("=" * 70)
    log(f"Source : {RAW_DIR}")
    log(f"Output : {PROCESSED_DIR}")
    log(f"Seed   : {RANDOM_STATE}")

    t0 = time.time()

    source_sizes = check_raw_files()
    df = load_and_label()
    df = remove_conflicts_and_duplicates(df)
    train_df, test_df = split(df)
    train_df, test_df = impute_rate_train_only(train_df, test_df)
    train_df = impute_nan_std_variance(train_df, "TRAIN")
    test_df = impute_nan_std_variance(test_df, "TEST")
    assert_clean(train_df, "TRAIN")
    assert_clean(test_df, "TEST")

    X_train = train_df[FEATURE_COLS].to_numpy()
    X_test = test_df[FEATURE_COLS].to_numpy()
    X_train_s, X_test_s, scaler = scale(X_train, X_test)
    y_train = train_df[LABEL_COL].to_numpy()
    y_test = test_df[LABEL_COL].to_numpy()
    verify_outputs(
        X_train, X_test, X_train_s, X_test_s, y_train, y_test, source_sizes
    )
    save_outputs(X_train_s, X_test_s, y_train, y_test, scaler)

    elapsed = time.time() - t0
    log(f"\n{'=' * 70}")
    log(f"PREPROCESSING COMPLETE in {elapsed:.1f}s")
    log(f"{'=' * 70}")

    # Save audit log
    audit_path = PROCESSED_DIR / "preprocessing_audit.log"
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "w") as f:
        f.write("\n".join(audit))
    log(f"Audit log -> {audit_path}")


if __name__ == "__main__":
    main()
