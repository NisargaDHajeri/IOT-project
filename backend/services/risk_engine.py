"""Security Risk Engine & Lockout State Machine.

Computes:
- Real-time security context parameters (battery, CPU, memory, latency, anomalies)
- Attempt velocity (frequency of failed attempts within sliding time window)
- Dynamic progressive risk escalation (LOW -> MEDIUM -> HIGH -> LOCKOUT)
- Timed lockout enforcement (default 60s) with automatic restoration
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, Optional
from database import get_db_connection
from config import (
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_DURATION_SECONDS,
    ATTEMPT_VELOCITY_WINDOW_SECONDS,
    VELOCITY_THRESHOLD_HIGH,
    DEVICE_ID,
)


def get_failed_attempts_count(device_id: str = DEVICE_ID) -> int:
    """Returns the count of consecutive failed attempts recorded in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT config_val FROM system_config WHERE config_key = 'failed_attempts_count';"
    )
    row = cursor.fetchone()
    conn.close()
    try:
        return int(row["config_val"]) if row else 0
    except (ValueError, TypeError):
        return 0


def increment_failed_attempts(device_id: str = DEVICE_ID) -> int:
    """Increments the failed attempt counter in SQLite and returns the new count."""
    current = get_failed_attempts_count(device_id)
    new_count = current + 1
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE system_config SET config_val = ?, updated_at = ? WHERE config_key = 'failed_attempts_count';",
        (str(new_count), now_iso),
    )
    cursor.execute(
        "UPDATE devices SET failed_attempts = ? WHERE device_id = ?;",
        (new_count, device_id),
    )
    conn.commit()
    conn.close()
    return new_count


def reset_failed_attempts(device_id: str = DEVICE_ID):
    """Resets the failed attempt counter to 0 upon successful authentication."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE system_config SET config_val = '0', updated_at = ? WHERE config_key = 'failed_attempts_count';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE devices SET failed_attempts = 0 WHERE device_id = ?;",
        (device_id,),
    )
    conn.commit()
    conn.close()


def calculate_attempt_velocity(window_seconds: int = ATTEMPT_VELOCITY_WINDOW_SECONDS) -> float:
    """Calculates the number of failed attempts within the sliding window."""
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(seconds=window_seconds)).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT COUNT(*) as cnt FROM authentication_events
           WHERE result = 'FAILED' AND timestamp >= ?;""",
        (window_start,),
    )
    row = cursor.fetchone()
    conn.close()
    return float(row["cnt"]) if row else 0.0


def is_system_locked_out() -> Tuple[bool, int]:
    """Checks if the system is currently in a LOCKOUT state.
    
    Returns: (is_locked_out, remaining_seconds)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT config_val FROM system_config WHERE config_key = 'lockout_until';"
    )
    row = cursor.fetchone()
    conn.close()

    if not row or not row["config_val"]:
        return False, 0

    try:
        lockout_dt = datetime.fromisoformat(row["config_val"])
        now_dt = datetime.now(timezone.utc)
        diff = int((lockout_dt - now_dt).total_seconds())
        if diff > 0:
            return True, diff
        else:
            # Lockout expired, clear lockout
            clear_system_lockout()
            return False, 0
    except Exception:
        return False, 0


def set_system_lockout(duration_seconds: int = LOCKOUT_DURATION_SECONDS):
    """Activates the LOCKOUT state for the specified duration."""
    now = datetime.now(timezone.utc)
    lockout_until = now + timedelta(seconds=duration_seconds)
    now_iso = now.isoformat()
    lockout_iso = lockout_until.isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE system_config SET config_val = ?, updated_at = ? WHERE config_key = 'lockout_until';",
        (lockout_iso, now_iso),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = 'LOCKOUT', updated_at = ? WHERE config_key = 'simulated_door_state';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = 'HIGH', updated_at = ? WHERE config_key = 'current_risk_level';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = 'HIGH', updated_at = ? WHERE config_key = 'active_pqc_profile';",
        (now_iso,),
    )
    conn.commit()
    conn.close()


def clear_system_lockout():
    """Clears the active lockout and restores normal security state."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE system_config SET config_val = '', updated_at = ? WHERE config_key = 'lockout_until';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = 'LOCKED', updated_at = ? WHERE config_key = 'simulated_door_state';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = 'LOW', updated_at = ? WHERE config_key = 'current_risk_level';",
        (now_iso,),
    )
    cursor.execute(
        "UPDATE system_config SET config_val = 'LOW', updated_at = ? WHERE config_key = 'active_pqc_profile';",
        (now_iso,),
    )
    conn.commit()
    conn.close()


def build_security_context(
    failed_count: int,
    source: str = "WEB_UI",
    device_id: str = DEVICE_ID,
) -> Dict[str, Any]:
    """Constructs a runtime security context based on real failure velocity and hardware telemetry."""
    velocity = calculate_attempt_velocity(window_seconds=30)
    
    # Simulate telemetry metrics correlated with attack velocity
    if failed_count == 0:
        cpu = 20
        mem = 25
        latency = 35
        net_anom = 0
        threat = 0
    elif failed_count <= 2:
        cpu = 35
        mem = 38
        latency = 45
        net_anom = 0
        threat = 0
    elif failed_count <= 4:
        cpu = 68
        mem = 62
        latency = 160
        net_anom = 1 if velocity >= 2 else 0
        threat = 0
    else:  # >= 5 failed attempts or rapid brute force
        cpu = 92
        mem = 88
        latency = 310
        net_anom = 1
        threat = 1

    return {
        "battery_level": 88,
        "cpu_utilization": cpu,
        "memory_usage": mem,
        "failed_auth_attempts": failed_count,
        "successful_auth_attempts": 0 if failed_count > 0 else 1,
        "communication_latency_ms": latency,
        "network_anomaly": net_anom,
        "threat_indicator": threat,
        "attempt_velocity": velocity,
        "source": source,
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
