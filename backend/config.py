"""Centralized System Configuration for Agentic AI Adaptive PQC Smart Door Lock."""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Load environment variables
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(BASE_DIR / ".env")

# Paths
DATABASE_DIR = BASE_DIR / "data"
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = Path(
    os.getenv("DATABASE_PATH", str(DATABASE_DIR / "smart_door.db"))
)

MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODELS_DIR / "risk_classifier.pkl"
DATA_PATH = DATABASE_DIR / "risk_dataset.csv"

FRONTEND_DIR = PROJECT_ROOT / "frontend"

# Device Configuration
DEVICE_ID = os.getenv("DEVICE_ID", "DOOR-ESP8266-001")
DEVICE_SECRET = os.getenv("DEVICE_SECRET", "")
FIRMWARE_VERSION = "1.0.0"
OWNER_INITIAL_PASSWORD = os.getenv("OWNER_INITIAL_PASSWORD", "")
INITIAL_DOOR_PIN = os.getenv("INITIAL_DOOR_PIN", "")
INITIAL_SECONDARY_DOOR_PIN = os.getenv("INITIAL_SECONDARY_DOOR_PIN", "")

# Security & Lockout Policy
MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", 5))
LOCKOUT_DURATION_SECONDS = int(os.getenv("LOCKOUT_DURATION_SECONDS", 60))
ATTEMPT_VELOCITY_WINDOW_SECONDS = int(os.getenv("ATTEMPT_VELOCITY_WINDOW_SECONDS", 30))
VELOCITY_THRESHOLD_HIGH = int(os.getenv("VELOCITY_THRESHOLD_HIGH", 3))

# Password Reset & OTP Policy
OTP_EXPIRY_SECONDS = int(os.getenv("OTP_EXPIRY_SECONDS", 120))  # 2 minutes
MAX_OTP_ATTEMPTS = int(os.getenv("MAX_OTP_ATTEMPTS", 3))
RESET_SESSION_TIMEOUT_SECONDS = int(os.getenv("RESET_SESSION_TIMEOUT_SECONDS", 300))

# Owner Session Policy
OWNER_SESSION_SECRET = os.getenv("OWNER_SESSION_SECRET", "")
OWNER_SESSION_DURATION_SECONDS = int(os.getenv("OWNER_SESSION_DURATION_SECONDS", 86400))  # 24 hours

# Simulated Door Policy
DOOR_AUTO_CLOSE_SECONDS = int(os.getenv("DOOR_AUTO_CLOSE_SECONDS", 5))

# Telemetry & Polling
GOOGLE_POLL_INTERVAL_SECONDS = int(os.getenv("GOOGLE_POLL_INTERVAL_SECONDS", 3))

# Google Sheets Configuration
GOOGLE_SCRIPT_URL = os.getenv("GOOGLE_SCRIPT_URL", "")
GOOGLE_SPREADSHEET_ID = os.getenv("GOOGLE_SPREADSHEET_ID", "")
GOOGLE_DEVICE_TOKEN = os.getenv("GOOGLE_DEVICE_TOKEN", "")
GOOGLE_CREDENTIALS_FILE = os.getenv("GOOGLE_CREDENTIALS_FILE", "")

# ML Feature Columns
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

# PQC Profiles Mapping
PQC_PROFILES = {
    "LOW": {
        "name": "LOW",
        "kem": "ML-KEM-512",
        "signature": "ML-DSA-44",
        "nist_level": 1,
        "description": "Standard quantum-resistant profile for normal low-risk operations.",
    },
    "MEDIUM": {
        "name": "MEDIUM",
        "kem": "ML-KEM-768",
        "signature": "ML-DSA-65",
        "nist_level": 3,
        "description": "Elevated quantum-resistant profile with increased parameter size for suspicious events.",
    },
    "HIGH": {
        "name": "HIGH",
        "kem": "ML-KEM-1024",
        "signature": "ML-DSA-87",
        "nist_level": 5,
        "description": "Maximum quantum-resistant security profile with maximum parameter strength during threat/lockout.",
    },
}
