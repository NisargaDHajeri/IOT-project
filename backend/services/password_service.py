"""Password & Credential Service for Door Lock.

Enforces:
- Single source of truth for door PIN
- Salted PBKDF2-HMAC-SHA256 verification
- Direct SHA-256 matching for ESP8266 keypad payloads
- Atomic password updates with credential versioning
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Tuple, Optional, List, Dict, Any
from database import get_db_connection, hash_secret, verify_secret_hash


def verify_door_pin(entered_pin: str) -> Tuple[bool, Optional[str]]:
    """Verifies an entered plaintext PIN against active credentials in SQLite."""
    if not entered_pin:
        return False, None

    entered_clean = str(entered_pin).strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, pin_hash, salt, user_alias FROM door_credentials WHERE is_active = 1 ORDER BY version DESC;"
    )
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        if verify_secret_hash(entered_clean, row["pin_hash"], row["salt"]):
            return True, row["user_alias"]

    return False, None


def verify_door_pin_hash(pin_sha256_hex: str) -> Tuple[bool, Optional[str]]:
    """Verifies a SHA-256 hex digest received from ESP8266 against current door credentials."""
    if not pin_sha256_hex:
        return False, None
    
    pin_sha256_clean = pin_sha256_hex.strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, pin_hash, salt, user_alias, pin_sha256 FROM door_credentials WHERE is_active = 1;"
    )
    rows = cursor.fetchall()
    conn.close()

    # 1. Direct match on stored active pin_sha256
    for row in rows:
        stored_sha256 = row["pin_sha256"] if "pin_sha256" in row.keys() and row["pin_sha256"] else ""
        if stored_sha256 and secrets.compare_digest(stored_sha256.lower(), pin_sha256_clean):
            return True, row["user_alias"]

    # Legacy records without a stored SHA-256 digest use the 4-digit fallback.
    for i in range(10000):
        test_pin = f"{i:04d}"
        if hashlib.sha256(test_pin.encode("utf-8")).hexdigest() == pin_sha256_clean:
            for row in rows:
                if verify_secret_hash(test_pin, row["pin_hash"], row["salt"]):
                    return True, row["user_alias"]
            break

    return False, None


def update_door_pin(new_pin: str, user_alias: str = "DAD", credential_name: str = "Primary Door PIN") -> Tuple[bool, str]:
    """Atomically updates the active door PIN, incrementing version and invalidating old PIN.
    
    Returns: (success, message)
    """
    if not new_pin or len(new_pin) < 4:
        return False, "New PIN must be at least 4 digits."

    new_hash, new_salt = hash_secret(new_pin)
    new_sha256 = hashlib.sha256(new_pin.encode("utf-8")).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Fetch current max version
        cursor.execute("SELECT MAX(version) as max_v FROM door_credentials;")
        res = cursor.fetchone()
        current_version = res["max_v"] if res and res["max_v"] else 1
        new_version = current_version + 1

        # Deactivate previous active credentials
        cursor.execute("UPDATE door_credentials SET is_active = 0, updated_at = ? WHERE is_active = 1;", (now_iso,))

        # Insert new active credential with pin_sha256
        cursor.execute(
            """INSERT INTO door_credentials (credential_name, pin_hash, salt, pin_sha256, version, is_active, user_alias, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
            (credential_name, new_hash, new_salt, new_sha256, new_version, user_alias, now_iso, now_iso),
        )

        conn.commit()
        return True, f"Door PIN successfully updated to Version {new_version}."
    except Exception as exc:
        conn.rollback()
        return False, f"Database transaction failed: {str(exc)}"
    finally:
        conn.close()


def get_active_credential_info() -> Dict[str, Any]:
    """Returns metadata about the active door credential (without exposing hashes)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, credential_name, version, user_alias, updated_at FROM door_credentials WHERE is_active = 1 LIMIT 1;"
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "credential_name": row["credential_name"],
            "version": row["version"],
            "user_alias": row["user_alias"],
            "last_updated": row["updated_at"],
            "is_configured": True,
        }
    return {
        "credential_name": "None",
        "version": 0,
        "user_alias": "None",
        "last_updated": "Never",
        "is_configured": False,
    }
