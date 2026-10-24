"""SQLite Database Management & Schema Layer for Smart Door Lock System.

Acts as the single local source of truth for:
- Owners
- Door credentials
- Devices
- Authentication events
- Security events
- Risk assessments
- Agent decisions
- Commands
- Reset sessions (AABB / OTP)
- Audit logs
- System configuration
"""

import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from config import (
    DATABASE_PATH,
    DEVICE_ID,
    DEVICE_SECRET,
    FIRMWARE_VERSION,
    INITIAL_DOOR_PIN,
    INITIAL_SECONDARY_DOOR_PIN,
    OWNER_INITIAL_PASSWORD,
)


def get_db_connection():
    """Returns a SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def hash_secret(secret_text: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Generates a secure PBKDF2-HMAC-SHA256 salted hash."""
    if not salt:
        salt = secrets.token_hex(16)
    # 100,000 iterations PBKDF2-HMAC-SHA256
    key = hashlib.pbkdf2_hmac(
        "sha256",
        secret_text.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    )
    return key.hex(), salt


def verify_secret_hash(secret_text: str, expected_hash: str, salt: str) -> bool:
    """Verifies a secret against a stored PBKDF2-HMAC-SHA256 hash in constant time."""
    computed_hash, _ = hash_secret(secret_text, salt)
    return secrets.compare_digest(computed_hash, expected_hash)


def init_db():
    """Initializes all SQLite database tables and seeds default records."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Owners Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS owners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # 2. Door Credentials Table (Single source of truth for door password)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS door_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_name TEXT NOT NULL,
        pin_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        pin_sha256 TEXT DEFAULT '',
        version INTEGER NOT NULL DEFAULT 1,
        is_active INTEGER NOT NULL DEFAULT 1,
        user_alias TEXT NOT NULL DEFAULT 'AUTHORIZED_USER',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # Schema Migration: Ensure pin_sha256 column exists
    cursor.execute("PRAGMA table_info(door_credentials);")
    cols = [col["name"] for col in cursor.fetchall()]
    if "pin_sha256" not in cols:
        cursor.execute("ALTER TABLE door_credentials ADD COLUMN pin_sha256 TEXT DEFAULT '';")

    # 3. Devices Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE NOT NULL,
        device_secret_hash TEXT NOT NULL,
        device_secret_salt TEXT NOT NULL,
        device_name TEXT NOT NULL,
        firmware_version TEXT NOT NULL,
        ip_address TEXT DEFAULT '—',
        rssi INTEGER DEFAULT 0,
        wifi_status TEXT DEFAULT 'DISCONNECTED',
        is_online INTEGER DEFAULT 0,
        device_state TEXT DEFAULT 'LOCKED',
        input_length INTEGER DEFAULT 0,
        keypad_state TEXT DEFAULT 'IDLE',
        failed_attempts INTEGER DEFAULT 0,
        last_seen TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # Schema Migration: Ensure input_length and keypad_state columns exist in devices table
    cursor.execute("PRAGMA table_info(devices);")
    device_cols = [col["name"] for col in cursor.fetchall()]
    if "input_length" not in device_cols:
        cursor.execute("ALTER TABLE devices ADD COLUMN input_length INTEGER DEFAULT 0;")
    if "keypad_state" not in device_cols:
        cursor.execute("ALTER TABLE devices ADD COLUMN keypad_state TEXT DEFAULT 'IDLE';")

    # 4. Authentication Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS authentication_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL, -- 'WEB_UI' or 'ESP8266_KEYPAD'
        attempted_hash TEXT,
        user TEXT NOT NULL,
        result TEXT NOT NULL, -- 'SUCCESS' or 'FAILED'
        failed_attempt_count INTEGER NOT NULL DEFAULT 0,
        ml_risk TEXT NOT NULL,
        agent_risk TEXT NOT NULL,
        pqc_kem TEXT NOT NULL,
        pqc_sig TEXT NOT NULL,
        action_taken TEXT NOT NULL,
        reason TEXT
    );
    """)

    # 5. Security Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        severity TEXT NOT NULL, -- 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        event_type TEXT NOT NULL,
        source TEXT NOT NULL,
        description TEXT NOT NULL,
        metadata_json TEXT
    );
    """)

    # 6. Risk Assessments Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        battery_level INTEGER,
        cpu_utilization INTEGER,
        memory_usage INTEGER,
        failed_auth_attempts INTEGER,
        communication_latency_ms INTEGER,
        network_anomaly INTEGER,
        threat_indicator INTEGER,
        ml_predicted_risk TEXT NOT NULL,
        ml_confidence_json TEXT NOT NULL,
        model_version TEXT NOT NULL
    );
    """)

    # 7. Agent Decisions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS agent_decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        decision_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        ml_risk TEXT NOT NULL,
        final_risk TEXT NOT NULL,
        escalation_applied INTEGER NOT NULL DEFAULT 0,
        escalation_reason TEXT,
        action TEXT NOT NULL,
        message TEXT NOT NULL,
        execution_status TEXT NOT NULL,
        pqc_kem TEXT NOT NULL,
        pqc_sig TEXT NOT NULL,
        reasoning_json TEXT,
        observations_json TEXT
    );
    """)

    # Additive migration: retain historical rows while storing model fusion.
    cursor.execute("PRAGMA table_info(agent_decisions);")
    decision_cols = {col["name"] for col in cursor.fetchall()}
    decision_migrations = {
        "device_risk": "TEXT",
        "network_risk": "TEXT",
        "network_prediction_json": "TEXT",
        "device_confidence_json": "TEXT",
        "network_confidence_json": "TEXT",
        "pqc_execution_mode": "TEXT",
    }
    for name, sql_type in decision_migrations.items():
        if name not in decision_cols:
            cursor.execute(
                f"ALTER TABLE agent_decisions ADD COLUMN {name} {sql_type};"
            )

    cursor.execute("PRAGMA table_info(authentication_events);")
    auth_cols = {col["name"] for col in cursor.fetchall()}
    auth_migrations = {
        "decision_id": "TEXT",
        "device_risk": "TEXT",
        "network_risk": "TEXT",
        "network_attack": "TEXT",
        "network_confidence_json": "TEXT",
    }
    for name, sql_type in auth_migrations.items():
        if name not in auth_cols:
            cursor.execute(
                f"ALTER TABLE authentication_events ADD COLUMN {name} {sql_type};"
            )

    # 8. Commands Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        command_id TEXT UNIQUE NOT NULL,
        device_id TEXT NOT NULL,
        command TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'PROCESSED', 'EXPIRED'
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        acknowledged_at TEXT
    );
    """)

    # 9. Reset Sessions Table (AABB / OTP Flow)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reset_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        device_id TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'OTP_VERIFIED', 'PASSWORD_RESET', 'EXPIRED', 'REVOKED', 'FAILED'
        attempt_count INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        verified_at TEXT,
        completed_at TEXT
    );
    """)

    # 10. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        source TEXT NOT NULL,
        details TEXT,
        status TEXT NOT NULL DEFAULT 'OK'
    );
    """)

    # 11. System Configuration Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config_key TEXT UNIQUE NOT NULL,
        config_val TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # Seed Default Owner if not exists
    cursor.execute("SELECT id FROM owners WHERE username = 'admin';")
    if not cursor.fetchone():
        if len(OWNER_INITIAL_PASSWORD) < 6:
            conn.close()
            raise RuntimeError(
                "Set OWNER_INITIAL_PASSWORD (at least 6 characters) in .env before first startup."
            )
        now_iso = datetime.now(timezone.utc).isoformat()
        h, s = hash_secret(OWNER_INITIAL_PASSWORD)
        cursor.execute(
            "INSERT INTO owners (username, password_hash, salt, status, created_at, updated_at) VALUES (?, ?, ?, 'ACTIVE', ?, ?)",
            ("admin", h, s, now_iso, now_iso),
        )

    # Seed the configured door credentials only on first initialization.
    cursor.execute("SELECT id FROM door_credentials WHERE is_active = 1;")
    if not cursor.fetchone():
        pins = (INITIAL_DOOR_PIN, INITIAL_SECONDARY_DOOR_PIN)
        if any(len(pin) not in range(4, 9) or not pin.isdecimal() for pin in pins):
            conn.close()
            raise RuntimeError(
                "Set INITIAL_DOOR_PIN and INITIAL_SECONDARY_DOOR_PIN to different 4-8 digit values in .env before first startup."
            )
        if INITIAL_DOOR_PIN == INITIAL_SECONDARY_DOOR_PIN:
            conn.close()
            raise RuntimeError("The initial door PIN values in .env must be different.")
        now_iso = datetime.now(timezone.utc).isoformat()
        h1, s1 = hash_secret(INITIAL_DOOR_PIN)
        sha1 = hashlib.sha256(INITIAL_DOOR_PIN.encode("utf-8")).hexdigest()
        cursor.execute(
            "INSERT INTO door_credentials (credential_name, pin_hash, salt, pin_sha256, version, is_active, user_alias, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 1, 'DAD', ?, ?)",
            ("Primary Door PIN", h1, s1, sha1, now_iso, now_iso),
        )
        h2, s2 = hash_secret(INITIAL_SECONDARY_DOOR_PIN)
        sha2 = hashlib.sha256(INITIAL_SECONDARY_DOOR_PIN.encode("utf-8")).hexdigest()
        cursor.execute(
            "INSERT INTO door_credentials (credential_name, pin_hash, salt, pin_sha256, version, is_active, user_alias, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 1, 'MOM', ?, ?)",
            ("Family Secondary PIN", h2, s2, sha2, now_iso, now_iso),
        )

    # Seed Default Device Record
    cursor.execute("SELECT id FROM devices WHERE device_id = ?;", (DEVICE_ID,))
    if not cursor.fetchone():
        if not DEVICE_SECRET:
            conn.close()
            raise RuntimeError("Set DEVICE_SECRET in .env before first startup.")
        now_iso = datetime.now(timezone.utc).isoformat()
        dh, ds = hash_secret(DEVICE_SECRET)
        cursor.execute(
            """INSERT INTO devices (device_id, device_secret_hash, device_secret_salt, device_name, firmware_version, ip_address, rssi, wifi_status, is_online, device_state, created_at)
               VALUES (?, ?, ?, 'Entrance NodeMCU Door Lock', ?, '—', 0, 'DISCONNECTED', 0, 'LOCKED', ?)""",
            (DEVICE_ID, dh, ds, FIRMWARE_VERSION, now_iso),
        )

    # Seed System Config Settings
    config_defaults = [
        ("simulated_door_state", "LOCKED"),
        ("security_mode", "NORMAL"),
        ("current_risk_level", "LOW"),
        ("active_pqc_profile", "LOW"),
        ("lockout_until", ""),
        ("failed_attempts_count", "0"),
    ]
    now_iso = datetime.now(timezone.utc).isoformat()
    for k, v in config_defaults:
        cursor.execute(
            "INSERT OR IGNORE INTO system_config (config_key, config_val, updated_at) VALUES (?, ?, ?);",
            (k, v, now_iso),
        )

    conn.commit()
    conn.close()


# Auto-initialize database on module import
init_db()
