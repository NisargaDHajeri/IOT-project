"""Device Management & Telemetry Service."""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from database import get_db_connection
from config import DEVICE_ID, FIRMWARE_VERSION


def update_device_heartbeat(
    device_id: str = DEVICE_ID,
    ip_address: str = "—",
    rssi: int = 0,
    wifi_status: str = "CONNECTED",
    device_state: str = "LOCKED",
    failed_attempts: Optional[int] = None,
    input_length: Optional[int] = None,
    keypad_state: Optional[str] = None,
) -> Dict[str, Any]:
    """Updates device hardware telemetry in SQLite upon heartbeat or event."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Build dynamic update statement based on provided fields
    updates = [
        "ip_address = ?",
        "rssi = ?",
        "wifi_status = ?",
        "is_online = 1",
        "device_state = ?",
        "last_seen = ?",
    ]
    params = [ip_address, rssi, wifi_status, device_state, now_iso]

    if failed_attempts is not None:
        updates.append("failed_attempts = ?")
        params.append(failed_attempts)

    if input_length is not None:
        updates.append("input_length = ?")
        params.append(int(input_length))

    if keypad_state is not None:
        updates.append("keypad_state = ?")
        params.append(str(keypad_state))

    params.append(device_id)
    sql = f"UPDATE devices SET {', '.join(updates)} WHERE device_id = ?;"
    cursor.execute(sql, tuple(params))

    conn.commit()
    conn.close()
    return get_device_status(device_id)


def get_device_status(device_id: str = DEVICE_ID) -> Dict[str, Any]:
    """Fetches device status, calculating online/offline based on last_seen heartbeat."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT device_id, device_name, firmware_version, ip_address, rssi,
                  wifi_status, is_online, device_state, input_length, keypad_state,
                  failed_attempts, last_seen
           FROM devices WHERE device_id = ?;""",
        (device_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {
            "device_id": device_id,
            "device_name": "ESP8266 Door Terminal",
            "firmware_version": FIRMWARE_VERSION,
            "ip_address": "—",
            "rssi": 0,
            "wifi_status": "DISCONNECTED",
            "is_online": False,
            "device_state": "LOCKED",
            "input_length": 0,
            "keypad_state": "IDLE",
            "failed_attempts": 0,
            "last_seen": None,
        }

    data = dict(row)
    data["input_length"] = int(data.get("input_length") or 0)
    data["keypad_state"] = str(data.get("keypad_state") or "IDLE")

    # Check if last seen is within 45 seconds
    if data.get("last_seen"):
        try:
            last_dt = datetime.fromisoformat(data["last_seen"])
            now_dt = datetime.now(timezone.utc)
            if (now_dt - last_dt).total_seconds() > 45:
                data["is_online"] = False
                data["wifi_status"] = "OFFLINE"
            else:
                data["is_online"] = True
        except Exception:
            data["is_online"] = False

    return data
