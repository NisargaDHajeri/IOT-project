"""Door Authentication & Legacy Adapter Service (SQLite-backed)."""

import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from database import get_db_connection
from services.password_service import verify_door_pin, verify_door_pin_hash
from services.audit_service import get_security_events
from services.device_service import get_device_status, update_device_heartbeat
from services.authentication_service import list_recent_events

LOCK = Lock()


def authenticate(password: str):
    """Authenticate via plaintext PIN."""
    valid, user = verify_door_pin(password)
    return {
        "success": valid,
        "user": user or "UNKNOWN",
        "reason": "Authorized credential" if valid else "Invalid credential",
    }


def authenticate_hash(pin_hash: str):
    """Authenticate via SHA-256 PIN hash."""
    valid, user = verify_door_pin_hash(pin_hash)
    return {
        "success": valid,
        "user": user or "UNKNOWN",
        "demo_pin": "••••",
        "reason": "Authorized cryptographic credential hash" if valid else "Unrecognized hash",
    }


def record_event(event_dict):
    """Records an event in the authentication log."""
    from services.authentication_service import _record_auth_event
    now_iso = datetime.now(timezone.utc).isoformat()
    evt_id = event_dict.get("event_id") or f"EVT-{secrets.token_hex(4).upper()}"
    pqc = event_dict.get("security_profile") or {}

    _record_auth_event(
        event_id=evt_id,
        timestamp=event_dict.get("timestamp") or now_iso,
        source=event_dict.get("source", "WEB_UI"),
        attempted_hash=event_dict.get("pin_attempt_hash", "••••"),
        user=event_dict.get("user", "UNKNOWN"),
        result=event_dict.get("result", "FAILED"),
        failed_count=event_dict.get("failed_attempt_number", 0),
        ml_risk=event_dict.get("ml_risk_level", "LOW"),
        agent_risk=event_dict.get("agent_risk_level", "LOW"),
        pqc_kem=pqc.get("kem", "ML-KEM-512"),
        pqc_sig=pqc.get("signature", "ML-DSA-44"),
        action_taken=event_dict.get("action", {}).get("action", "RECORD"),
        reason=event_dict.get("reason", "Event recorded"),
    )
    event_dict["event_id"] = evt_id
    event_dict["timestamp"] = now_iso
    return event_dict


def list_events(limit: int = 50):
    return list_recent_events(limit)


def update_device_status(status_dict):
    return update_device_heartbeat(
        device_id=status_dict.get("device_id", "DOOR-001"),
        ip_address=status_dict.get("ip_address", "—"),
        rssi=status_dict.get("rssi", 0),
        wifi_status=status_dict.get("wifi_status", "CONNECTED"),
        device_state=status_dict.get("device_state", "LOCKED"),
    )
