"""Password Reset & Cryptographic OTP Engine.

Manages:
- AABB reset initiation flow
- Cryptographically secure 6-digit OTP generation via Python secrets module
- 2-Minute single-use TTL
- SQLite persistence of hashed OTPs
- Multi-step validation: AABB -> OTP_REQUIRED -> OTP_VERIFIED -> NEW_PASSWORD -> CONFIRMED -> SUCCESS
"""

import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, Any
from database import get_db_connection, hash_secret, verify_secret_hash
from services.password_service import update_door_pin
from config import OTP_EXPIRY_SECONDS, MAX_OTP_ATTEMPTS, RESET_SESSION_TIMEOUT_SECONDS, DEVICE_ID

# In-memory transient storage for active OTP plaintext (accessible only to authenticated Owner during active TTL)
# Key: session_id -> {plaintext_otp, expires_timestamp}
_ACTIVE_PLAINTEXT_OTPS: Dict[str, Dict[str, Any]] = {}


def generate_secure_otp() -> str:
    """Generates a cryptographically secure 6-digit numeric OTP (100000 - 999999)."""
    return str(secrets.randbelow(900000) + 100000)


def create_reset_session(device_id: str = DEVICE_ID) -> Dict[str, Any]:
    """Initiates an active password reset session and generates a 6-digit OTP with 2-minute validity.
    
    If an unexpired session already exists, revokes or updates it to ensure only one active OTP exists.
    """
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=OTP_EXPIRY_SECONDS)
    now_iso = now.isoformat()
    expires_iso = expires.isoformat()

    session_id = f"RST-{secrets.token_hex(4).upper()}"
    plaintext_otp = generate_secure_otp()
    otp_hash, salt = hash_secret(plaintext_otp)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Expire previous pending sessions
    cursor.execute(
        "UPDATE reset_sessions SET status = 'REVOKED' WHERE device_id = ? AND status IN ('PENDING', 'OTP_VERIFIED');",
        (device_id,),
    )

    cursor.execute(
        """INSERT INTO reset_sessions (session_id, device_id, otp_hash, salt, status, attempt_count, max_attempts, created_at, expires_at)
           VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?)""",
        (session_id, device_id, otp_hash, salt, MAX_OTP_ATTEMPTS, now_iso, expires_iso),
    )
    conn.commit()
    conn.close()

    # Store transient plaintext for Owner UI display
    _ACTIVE_PLAINTEXT_OTPS[session_id] = {
        "otp": plaintext_otp,
        "expires_timestamp": time.time() + OTP_EXPIRY_SECONDS,
        "device_id": device_id,
    }

    return {
        "session_id": session_id,
        "device_id": device_id,
        "otp": plaintext_otp,
        "expires_in_seconds": OTP_EXPIRY_SECONDS,
        "expires_at": expires_iso,
        "status": "ACTIVE",
    }


def trigger_aabb_reset(device_id: str = DEVICE_ID) -> Dict[str, Any]:
    """Triggered when physical keypad enters 'AABB' sequence. Creates/registers a reset requirement."""
    # Check if there's already an active unexpired session
    session = get_active_reset_session(device_id)
    if session and session.get("status") in ["PENDING", "OTP_VERIFIED"]:
        return {
            "status": "RESET_MODE_ACTIVE",
            "message": "Enter 6-digit Owner OTP.",
            "session_id": session["session_id"],
            "state": session["status"],
        }
    
    # Otherwise create a pending reset session container awaiting Owner OTP generation
    now_iso = datetime.now(timezone.utc).isoformat()
    session_id = f"AABB-{secrets.token_hex(4).upper()}"
    return {
        "status": "RESET_MODE_INITIALIZED",
        "message": "AABB reset initiated. Please generate OTP from Owner Dashboard.",
        "session_id": session_id,
        "state": "WAITING_OWNER_OTP",
    }


def get_active_reset_session(device_id: str = DEVICE_ID) -> Optional[Dict[str, Any]]:
    """Fetches the latest active reset session for a device with calculated remaining time."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT session_id, device_id, status, attempt_count, max_attempts, created_at, expires_at, verified_at
           FROM reset_sessions
           WHERE device_id = ? AND status IN ('PENDING', 'OTP_VERIFIED')
           ORDER BY id DESC LIMIT 1;""",
        (device_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    # Check expiration
    expires_dt = datetime.fromisoformat(row["expires_at"])
    now_dt = datetime.now(timezone.utc)
    remaining_seconds = int((expires_dt - now_dt).total_seconds())

    if remaining_seconds <= 0:
        # Mark expired in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE reset_sessions SET status = 'EXPIRED' WHERE session_id = ?;",
            (row["session_id"],),
        )
        conn.commit()
        conn.close()
        _ACTIVE_PLAINTEXT_OTPS.pop(row["session_id"], None)
        return {
            "session_id": row["session_id"],
            "device_id": row["device_id"],
            "status": "EXPIRED",
            "remaining_seconds": 0,
            "otp": None,
        }

    # Retrieve transient plaintext OTP if present
    pt_entry = _ACTIVE_PLAINTEXT_OTPS.get(row["session_id"])
    plaintext = pt_entry["otp"] if pt_entry else None

    return {
        "session_id": row["session_id"],
        "device_id": row["device_id"],
        "status": row["status"],
        "attempt_count": row["attempt_count"],
        "max_attempts": row["max_attempts"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "remaining_seconds": max(0, remaining_seconds),
        "otp": plaintext,
    }


def verify_reset_otp(device_id: str, entered_otp: str) -> Tuple[bool, str]:
    """Verifies an entered 6-digit OTP against the active session.
    
    Returns: (is_valid, message)
    """
    if not entered_otp:
        return False, "OTP is required."

    entered_clean = entered_otp.strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT session_id, otp_hash, salt, status, attempt_count, max_attempts, expires_at
           FROM reset_sessions
           WHERE device_id = ? AND status = 'PENDING'
           ORDER BY id DESC LIMIT 1;""",
        (device_id,),
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return False, "No active OTP reset session found. Please generate a new OTP."

    # Check expiration
    expires_dt = datetime.fromisoformat(row["expires_at"])
    now_dt = datetime.now(timezone.utc)
    if now_dt > expires_dt:
        cursor.execute(
            "UPDATE reset_sessions SET status = 'EXPIRED' WHERE session_id = ?;",
            (row["session_id"],),
        )
        conn.commit()
        conn.close()
        _ACTIVE_PLAINTEXT_OTPS.pop(row["session_id"], None)
        return False, "Reset OTP has expired. Please initiate a new reset."

    # Verify attempt limit
    attempts = row["attempt_count"] + 1
    if not verify_secret_hash(entered_clean, row["otp_hash"], row["salt"]):
        if attempts >= row["max_attempts"]:
            cursor.execute(
                "UPDATE reset_sessions SET status = 'FAILED', attempt_count = ? WHERE session_id = ?;",
                (attempts, row["session_id"]),
            )
            conn.commit()
            conn.close()
            _ACTIVE_PLAINTEXT_OTPS.pop(row["session_id"], None)
            return False, f"Maximum OTP attempts exceeded ({row['max_attempts']}). Reset session cancelled."
        else:
            cursor.execute(
                "UPDATE reset_sessions SET attempt_count = ? WHERE session_id = ?;",
                (attempts, row["session_id"]),
            )
            conn.commit()
            conn.close()
            remaining = row["max_attempts"] - attempts
            return False, f"Invalid OTP entered. {remaining} attempt(s) remaining."

    # Success: transition to OTP_VERIFIED
    now_iso = now_dt.isoformat()
    cursor.execute(
        "UPDATE reset_sessions SET status = 'OTP_VERIFIED', verified_at = ? WHERE session_id = ?;",
        (now_iso, row["session_id"]),
    )
    conn.commit()
    conn.close()

    # Invalidate plaintext OTP so it cannot be replayed or displayed again
    _ACTIVE_PLAINTEXT_OTPS.pop(row["session_id"], None)

    return True, "OTP verified successfully. Please enter and confirm new door password."


def complete_password_reset(device_id: str, new_pin: str, confirm_pin: str) -> Tuple[bool, str]:
    """Completes the password reset process after successful OTP verification.
    
    Returns: (success, message)
    """
    if not new_pin or not confirm_pin:
        return False, "New PIN and confirmation are required."

    if new_pin != confirm_pin:
        return False, "Password confirmation does not match."

    if len(new_pin) < 4:
        return False, "PIN must be at least 4 digits."

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT session_id, status FROM reset_sessions
           WHERE device_id = ? AND status = 'OTP_VERIFIED'
           ORDER BY id DESC LIMIT 1;""",
        (device_id,),
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return False, "No verified OTP session found. Please verify OTP first."

    session_id = row["session_id"]
    now_iso = datetime.now(timezone.utc).isoformat()

    # Update door PIN atomically
    success, msg = update_door_pin(new_pin, user_alias="DAD", credential_name="Primary Door PIN (Reset)")
    if not success:
        conn.close()
        return False, msg

    # Mark reset session complete
    cursor.execute(
        "UPDATE reset_sessions SET status = 'PASSWORD_RESET', completed_at = ? WHERE session_id = ?;",
        (now_iso, session_id),
    )
    # Set door state to LOCKED and clear any lingering lockout
    cursor.execute(
        "UPDATE system_config SET config_val = 'LOCKED', updated_at = ? WHERE config_key = 'simulated_door_state';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = '0', updated_at = ? WHERE config_key = 'active_failed_streak';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = 'LOW', updated_at = ? WHERE config_key = 'current_risk_level';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = '', updated_at = ? WHERE config_key = 'lockout_until';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE devices SET failed_attempts = 0, device_state = 'LOCKED';",
    )
    conn.commit()
    conn.close()

    return True, "Password reset successful. Old password invalidated; new password is now active."


def complete_password_reset_hash(device_id: str, new_pin_hash: str, confirm_pin_hash: str) -> Tuple[bool, str]:
    """Complete a hardware reset without transmitting the new PIN plaintext."""
    allowed = set("0123456789abcdef")
    if (len(new_pin_hash) != 64 or len(confirm_pin_hash) != 64
            or set(new_pin_hash) - allowed or set(confirm_pin_hash) - allowed):
        return False, "Two SHA-256 PIN hashes are required."
    if not secrets.compare_digest(new_pin_hash, confirm_pin_hash):
        return False, "Password confirmation does not match."

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT session_id FROM reset_sessions WHERE device_id = ? AND status = 'OTP_VERIFIED'
           ORDER BY id DESC LIMIT 1;""", (device_id,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, "No verified OTP session found. Please verify OTP first."
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        # The ESP can later authenticate this credential by direct SHA-256 comparison.
        # A random PBKDF2 value preserves the non-null legacy schema without retaining
        # a reversible or plaintext representation of the new PIN.
        placeholder_hash, placeholder_salt = hash_secret(secrets.token_hex(32))
        cursor.execute("UPDATE door_credentials SET is_active = 0 WHERE is_active = 1;")
        cursor.execute("SELECT COALESCE(MAX(version), 0) + 1 AS version FROM door_credentials;")
        version = cursor.fetchone()["version"]
        cursor.execute(
            """INSERT INTO door_credentials
               (credential_name, pin_hash, salt, pin_sha256, version, is_active, user_alias, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 1, 'DAD', ?, ?)""",
            ("Primary Door PIN (Hardware Reset)", placeholder_hash, placeholder_salt,
             new_pin_hash, version, now_iso, now_iso),
        )
        cursor.execute(
            "UPDATE reset_sessions SET status = 'PASSWORD_RESET', completed_at = ? WHERE session_id = ?;",
            (now_iso, row["session_id"]),
        )
        cursor.execute("UPDATE devices SET failed_attempts = 0, device_state = 'LOCKED' WHERE device_id = ?;", (device_id,))
        conn.commit()
        return True, "Password reset successful. The new PIN was never sent to the backend."
    except Exception:
        conn.rollback()
        return False, "Database transaction failed."
    finally:
        conn.close()


def revoke_reset_session(device_id: str = DEVICE_ID) -> Tuple[bool, str]:
    """Revokes any active reset sessions for the given device."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE reset_sessions SET status = 'REVOKED' WHERE device_id = ? AND status IN ('PENDING', 'OTP_VERIFIED');",
        (device_id,),
    )
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    # Clear active plaintexts
    for sid in list(_ACTIVE_PLAINTEXT_OTPS.keys()):
        if _ACTIVE_PLAINTEXT_OTPS[sid].get("device_id") == device_id:
            _ACTIVE_PLAINTEXT_OTPS.pop(sid, None)

    if affected > 0:
        return True, "Password reset session has been revoked."
    return False, "No active reset session to revoke."
