"""Synthetic Security Dataset Generator for Smart Door Lock Evaluation."""

import pandas as pd
import numpy as np
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "risk_dataset.csv"


def generate_synthetic_dataset(num_samples: int = 3000, save: bool = True) -> pd.DataFrame:
    """Generates synthetic security events corresponding to LOW, MEDIUM, and HIGH risk profiles."""
    np.random.seed(42)
    n_per_class = num_samples // 3

    # 1. LOW Risk (Normal authorized traffic)
    low_data = {
        "battery_level": np.random.randint(60, 100, n_per_class),
        "cpu_utilization": np.random.randint(10, 45, n_per_class),
        "memory_usage": np.random.randint(15, 50, n_per_class),
        "failed_auth_attempts": np.random.choice([0, 1], n_per_class, p=[0.85, 0.15]),
        "successful_auth_attempts": np.random.randint(1, 10, n_per_class),
        "communication_latency_ms": np.random.randint(20, 80, n_per_class),
        "network_anomaly": np.zeros(n_per_class, dtype=int),
        "threat_indicator": np.zeros(n_per_class, dtype=int),
        "risk_level": ["LOW"] * n_per_class,
    }

    # 2. MEDIUM Risk (Suspicious / repetitive attempts)
    med_data = {
        "battery_level": np.random.randint(40, 90, n_per_class),
        "cpu_utilization": np.random.randint(45, 75, n_per_class),
        "memory_usage": np.random.randint(50, 75, n_per_class),
        "failed_auth_attempts": np.random.randint(2, 4, n_per_class),
        "successful_auth_attempts": np.random.choice([0, 1], n_per_class, p=[0.7, 0.3]),
        "communication_latency_ms": np.random.randint(80, 200, n_per_class),
        "network_anomaly": np.random.choice([0, 1], n_per_class, p=[0.6, 0.4]),
        "threat_indicator": np.zeros(n_per_class, dtype=int),
        "risk_level": ["MEDIUM"] * n_per_class,
    }

    # 3. HIGH Risk (Brute force attack / intrusion attempt)
    high_data = {
        "battery_level": np.random.randint(20, 85, n_per_class),
        "cpu_utilization": np.random.randint(75, 100, n_per_class),
        "memory_usage": np.random.randint(75, 98, n_per_class),
        "failed_auth_attempts": np.random.randint(4, 12, n_per_class),
        "successful_auth_attempts": np.zeros(n_per_class, dtype=int),
        "communication_latency_ms": np.random.randint(180, 450, n_per_class),
        "network_anomaly": np.random.choice([0, 1], n_per_class, p=[0.1, 0.9]),
        "threat_indicator": np.random.choice([0, 1], n_per_class, p=[0.2, 0.8]),
        "risk_level": ["HIGH"] * n_per_class,
    }

    df_low = pd.DataFrame(low_data)
    df_med = pd.DataFrame(med_data)
    df_high = pd.DataFrame(high_data)

    df = pd.concat([df_low, df_med, df_high], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    if save:
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(DATA_PATH, index=False)
        print(f"Generated synthetic dataset saved to {DATA_PATH} ({len(df)} samples)")

    return df


if __name__ == "__main__":
    generate_synthetic_dataset()
