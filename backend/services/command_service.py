"""Hardware & System Command Queue Service.

Features:
- Unique command_id generation with expiration timestamps
- Replay prevention (duplicate command rejection)
- Command status lifecycle: PENDING -> PROCESSED / ACKNOWLEDGED / EXPIRED
"""

import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from database import get_db_connection
from config import DEVICE_ID

ALLOWED_COMMANDS = {
    "AUTHENTICATION_SUCCESS",
    "AUTHENTICATION_FAILURE",
    "UNLOCK_SIMULATION",
    "DENY",
    "LOCKOUT",
    "RESET_REQUESTED",
    "OTP_REQUIRED",
    "OTP_VALID",
    "OTP_INVALID",
    "PASSWORD_RESET_SUCCESS",
    "PASSWORD_RESET_FAILED",
}


def queue_command(
    device_id: str,
    command: str,
    risk_level: str = "LOW",
    reason: str = "",
    ttl_seconds: int = 60,
) -> Dict[str, Any]:
    """Creates a command in SQLite for the ESP8266 device to consume."""
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command '{command}' is not in allowed command list.")

    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)
    now_iso = now.isoformat()
    expires_iso = expires.isoformat()
    command_id = f"CMD-{secrets.token_hex(4).upper()}"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO commands (command_id, device_id, command, risk_level, reason, status, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)""",
        (command_id, device_id, command, risk_level, reason, now_iso, expires_iso),
    )
    conn.commit()
    conn.close()

    return {
        "command_id": command_id,
        "device_id": device_id,
        "command": command,
        "risk_level": risk_level,
        "reason": reason,
        "status": "PENDING",
        "created_at": now_iso,
        "expires_at": expires_iso,
    }


def get_pending_commands(device_id: str = DEVICE_ID) -> List[Dict[str, Any]]:
    """Retrieves unacknowledged, unexpired commands for the device."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Expire stale commands
    cursor.execute(
        "UPDATE commands SET status = 'EXPIRED' WHERE status = 'PENDING' AND expires_at < ?;",
        (now_iso,),
    )
    conn.commit()

    # Fetch pending
    cursor.execute(
        """SELECT command_id, device_id, command, risk_level, reason, created_at, expires_at
           FROM commands
           WHERE device_id = ? AND status = 'PENDING'
           ORDER BY id ASC;""",
        (device_id,),
    )
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def acknowledge_command(command_id: str, device_id: str = DEVICE_ID) -> bool:
    """Marks a command as acknowledged/processed by the device."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE commands
           SET status = 'PROCESSED', acknowledged_at = ?
           WHERE command_id = ? AND device_id = ? AND status = 'PENDING';""",
        (now_iso, command_id, device_id),
    )
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0
