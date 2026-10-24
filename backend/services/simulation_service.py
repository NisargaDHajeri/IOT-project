"""Simulated Door State & Actuation Service."""

from datetime import datetime, timezone
from typing import Dict, Any
from database import get_db_connection


def get_door_state() -> str:
    """Returns the current simulated door state (LOCKED, OPEN, LOCKOUT, etc.)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT config_val FROM system_config WHERE config_key = 'simulated_door_state';"
    )
    row = cursor.fetchone()
    conn.close()
    return row["config_val"] if row else "LOCKED"


def set_door_state(new_state: str) -> str:
    """Updates the simulated door state in SQLite."""
    allowed = {"LOCKED", "AUTHENTICATING", "UNLOCKING", "OPEN", "LOCKING", "LOCKOUT", "ERROR"}
    state = new_state.upper()
    if state not in allowed:
        state = "LOCKED"

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE system_config SET config_val = ?, updated_at = ? WHERE config_key = 'simulated_door_state';",
        (state, now_iso),
    )
    cursor.execute(
        "UPDATE devices SET device_state = ?;",
        (state,),
    )
    conn.commit()
    conn.close()
    return state


def lock_door() -> Dict[str, Any]:
    """Manually forces door state to LOCKED."""
    s = set_door_state("LOCKED")
    return {"door_state": s, "message": "Simulated door locked successfully."}


def unlock_door() -> Dict[str, Any]:
    """Manually forces door state to OPEN."""
    s = set_door_state("OPEN")
    return {"door_state": s, "message": "Simulated door unlocked successfully."}
