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
def check_raw_files() -> None:
    log("STEP 0 -- Verifying raw CSV files (read-only check)")
    for fname in FILE_LABEL_MAP:
        path = RAW_DIR / fname
        if not path.exists():
            log(f"  ERROR: Missing file: {path}")
            sys.exit(1)
        log(f"  OK  {fname}  ({path.stat().st_size / 1e6:.1f} MB)")
    log("  All 6 source files confirmed present.")


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
# STEP 2 -- Drop exact duplicate rows (features only, before any split)
# =============================================================================
def drop_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    log("\nSTEP 2 -- Dropping exact duplicate rows (before split -- prevents leakage)")
    before = len(df)
    df = df.drop_duplicates(subset=FEATURE_COLS)
    after  = len(df)
    dropped = before - after
    log(f"  Before: {before:,}  |  After: {after:,}  |  Dropped: {dropped:,} ({100*dropped/before:.2f}%)")
    log(f"  Class distribution after dedup:")
    for label, count in df[LABEL_COL].value_counts().items():
        log(f"    {label:<30}  {count:>8,}  ({100*count/after:.2f}%)")
    return df.reset_index(drop=True)


# =============================================================================
# STEP 3 -- Fix Inf in 'Rate' -> per-class non-inf median
# =============================================================================
def fix_inf_rate(df: pd.DataFrame) -> pd.DataFrame:
    log("\nSTEP 3 -- Replacing inf values in 'Rate' with per-class non-inf median")
    inf_mask  = np.isinf(df["Rate"])
    total_inf = int(inf_mask.sum())
    log(f"  Total inf cells in 'Rate': {total_inf}")

    if total_inf == 0:
        log("  No inf values -- skipping.")
        return df

    # Convert inf -> NaN so pandas median() ignores them
    df["Rate"] = df["Rate"].replace([np.inf, -np.inf], np.nan)

    # Per-class median from finite (non-NaN) values
    per_class_median = df.groupby(LABEL_COL)["Rate"].median()

    # ── GUARD: every class with inf rows must have a valid (finite) median ──
    # If a class had ALL rows as inf, median() returns NaN -- imputation would
    # silently propagate NaN. Fail explicitly instead.
    bad_classes = [
        cls for cls, med in per_class_median.items()
        if pd.isna(med) or not np.isfinite(med)
    ]
    if bad_classes:
        log(f"  ABORT: Cannot impute Rate for class(es) {bad_classes} --")
        log(f"         all Rate values are inf/NaN for those classes.")
        log(f"         Inspect the raw CSVs before proceeding.")
        sys.exit(1)

    log("  Per-class non-inf Rate medians (all verified finite):")
    for cls, med in per_class_median.items():
        log(f"    {cls:<30}  {med:.6f}  [VALID]")

    # Fill NaN (was inf) with per-class median
    for cls, med in per_class_median.items():
        mask     = (df[LABEL_COL] == cls) & df["Rate"].isna()
        n_filled = int(mask.sum())
        if n_filled > 0:
            df.loc[mask, "Rate"] = med
            log(f"    Filled {n_filled} inf -> {med:.6f} for class '{cls}'")

    remaining_nan = int(df["Rate"].isna().sum())
    remaining_inf = int(np.isinf(df["Rate"]).sum())
    log(f"  After fix -- Rate NaN: {remaining_nan}  Rate Inf: {remaining_inf}")
    return df


# =============================================================================
# STEP 4 -- Impute NaN in 'Std' and 'Variance' with 0.0
# =============================================================================
def impute_nan_std_variance(df: pd.DataFrame) -> pd.DataFrame:
    log("\nSTEP 4 -- Imputing NaN in 'Std' and 'Variance' with 0.0")
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
# STEP 5 -- Data quality assertion
# =============================================================================
def assert_clean(df: pd.DataFrame) -> None:
    log("\nSTEP 5 -- Data quality assertion (must be zero NaN and zero Inf)")
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
# STEP 6 -- Stratified 80/20 train/test split
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
    log("\nSTEP 6 -- Stratified 80/20 train/test split")
    X = df[FEATURE_COLS].values
    y = df[LABEL_COL].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    n_total = len(X_train) + len(X_test)
    log(f"  Train: {len(X_train):,} rows ({100*len(X_train)/n_total:.1f}%)")
    log(f"  Test : {len(X_test):,} rows ({100*len(X_test)/n_total:.1f}%)")

    log(f"\n  Class distribution in TRAIN:")
    for cls, cnt in pd.Series(y_train).value_counts().items():
        log(f"    {cls:<30}  {cnt:>8,}  ({100*cnt/len(y_train):.2f}%)")

    log(f"\n  Class distribution in TEST:")
    for cls, cnt in pd.Series(y_test).value_counts().items():
        log(f"    {cls:<30}  {cnt:>8,}  ({100*cnt/len(y_test):.2f}%)")

    return X_train, X_test, y_train, y_test


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


# =============================================================================
# STEP 8 -- Save all outputs to ciciot_experiment/data/processed/
# =============================================================================
def save_outputs(
    X_train_s: np.ndarray,
    X_test_s: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    scaler: RobustScaler,
) -> None:
    log("\nSTEP 8 -- Saving outputs to ciciot_experiment/data/processed/")
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

    check_raw_files()
    df = load_and_label()
    df = drop_duplicates(df)
    df = fix_inf_rate(df)
    df = impute_nan_std_variance(df)
    assert_clean(df)
    X_train, X_test, y_train, y_test = split(df)
    X_train_s, X_test_s, scaler = scale(X_train, X_test)
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
