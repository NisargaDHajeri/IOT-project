"""CICIoT2023 network attack classifier for supplied flow telemetry.

The service performs inference only. It does not capture live packets.
"""

from numbers import Real
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "ciciot_experiment" / "models" / "ciciot_random_forest.pkl"
SCALER_PATH = (
    PROJECT_ROOT / "ciciot_experiment" / "data" / "processed"
    / "robust_scaler.pkl"
)

NETWORK_FEATURE_COLUMNS = (
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number",
    "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH",
    "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv",
    "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
    "IAT", "Number", "Variance",
)

_model = None
_scaler = None
_feature_columns = None


def reset_model_cache() -> None:
    """Clear cached artifacts, primarily for tests and explicit reloads."""
    global _model, _scaler, _feature_columns
    _model = None
    _scaler = None
    _feature_columns = None


def _load_artifacts() -> Tuple[Any, Any, Tuple[str, ...]]:
    """Load and validate model/scaler artifacts once."""
    global _model, _scaler, _feature_columns

    if _model is None:
        if not MODEL_PATH.is_file():
            raise FileNotFoundError("CICIoT2023 network model is unavailable.")
        if not SCALER_PATH.is_file():
            raise FileNotFoundError("CICIoT2023 network scaler is unavailable.")

        saved = joblib.load(MODEL_PATH)
        model = saved["model"]
        feature_columns = tuple(saved["feature_columns"])
        scaler = joblib.load(SCALER_PATH)
        if feature_columns != NETWORK_FEATURE_COLUMNS:
            raise RuntimeError("Network model feature schema is incompatible.")

        _model = model
        _scaler = scaler
        _feature_columns = feature_columns

    return _model, _scaler, _feature_columns


def validate_network_features(features: Any) -> Dict[str, float]:
    """Require exactly 39 numeric finite JSON values and return model order."""
    if not isinstance(features, dict):
        raise ValueError("network_features must be a JSON object.")

    expected = set(NETWORK_FEATURE_COLUMNS)
    provided = set(features)
    missing = sorted(expected - provided)
    extra = sorted(provided - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing fields: {missing}")
        if extra:
            details.append(f"unexpected fields: {extra}")
        raise ValueError("Invalid network feature set (" + "; ".join(details) + ").")

    values: Dict[str, float] = {}
    for name in NETWORK_FEATURE_COLUMNS:
        value = features[name]
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"Network feature '{name}' must be a JSON number.")
        numeric_value = float(value)
        if not np.isfinite(numeric_value):
            raise ValueError(f"Network feature '{name}' must be finite.")
        values[name] = numeric_value
    return values


def predict_network_threat(features: Any) -> Dict[str, Any]:
    """Predict a network attack class from 39 supplied raw CICIoT features."""
    values = validate_network_features(features)
    model, scaler, feature_columns = _load_artifacts()
    row = pd.DataFrame([[values[name] for name in feature_columns]],
                       columns=feature_columns)

    # The saved scaler was fitted with an ndarray; the forest expects the
    # original named columns. Keep each estimator's input representation.
    scaled_values = scaler.transform(row.to_numpy())
    scaled = pd.DataFrame(scaled_values, columns=feature_columns)
    prediction = str(model.predict(scaled)[0])
    probabilities = model.predict_proba(scaled)[0]
    confidence = {
        str(label): round(float(probability), 4)
        for label, probability in zip(model.classes_, probabilities)
    }
    return {
        "predicted_attack": prediction,
        "confidence": confidence,
        "max_confidence": round(float(np.max(probabilities)), 4),
        "model": "CICIoT2023-RandomForest",
        "telemetry_source": "SUPPLIED_FLOW_FEATURES",
        "live_capture": False,
    }


def network_risk_from_prediction(prediction: Dict[str, Any]) -> str:
    """Conservatively map network attack class and confidence to risk."""
    if prediction["predicted_attack"] == "BenignTraffic":
        return "LOW"
    if float(prediction["max_confidence"]) < 0.70:
        return "MEDIUM"
    return "HIGH"
