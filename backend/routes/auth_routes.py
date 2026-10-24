"""Public Door Authentication & Door Control Routes."""

from flask import Blueprint, request, jsonify
import logging
from services.authentication_service import authenticate_access, list_recent_events
from services.simulation_service import get_door_state, lock_door, unlock_door
from services.risk_engine import get_failed_attempts_count, is_system_locked_out
from services.pqc_service import get_pqc_profile
from database import get_db_connection

auth_bp = Blueprint("auth_bp", __name__)
logger = logging.getLogger(__name__)


@auth_bp.post("/api/authenticate")
@auth_bp.post("/api/door/auth")
@auth_bp.post("/door/auth")
@auth_bp.post("/analyze")
def public_authenticate():
    """Authenticates public door password entered on the locked dashboard."""
    try:
        body = request.get_json(silent=True) or {}
        password = str(body.get("password", "")).strip()

        if not password:
            return jsonify({"error": "Password PIN is required"}), 400

        result = authenticate_access(
            credential_input=password,
            source="WEB_UI",
            is_hash=False,
        )
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Door authentication processing failed")
        return jsonify({"error": "Authentication processing failed."}), 500


@auth_bp.get("/api/door/status")
def door_status():
    """Fetches public door telemetry (door state, risk level, PQC profile, failed attempts)."""
    try:
        door_state = get_door_state()
        failed_count = get_failed_attempts_count()
        is_locked, remaining_lockout = is_system_locked_out()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT config_val FROM system_config WHERE config_key = 'current_risk_level';")
        r_row = cursor.fetchone()
        current_risk = r_row["config_val"] if r_row else "LOW"
        conn.close()

        profile = get_pqc_profile(current_risk)
        latest = list_recent_events(1)
        latest_event = latest[0] if latest else None

        return jsonify({
            "door_state": "LOCKOUT" if is_locked else door_state,
            "risk_level": current_risk,
            "failed_attempts": failed_count,
            "lockout_active": is_locked,
            "lockout_remaining_seconds": remaining_lockout,
            "security_mode": "LOCKOUT" if is_locked else "NORMAL",
            "pqc_profile": {
                "name": profile["name"],
                "kem": profile["kem"],
                "signature": profile["signature"],
                "nist_level": profile["nist_level"],
            },
            "latest_security_decision": ({
                "event_id": latest_event.get("event_id"),
                "decision_id": latest_event.get("decision_id"),
                "timestamp": latest_event.get("timestamp"),
                "source": latest_event.get("source"),
                "result": latest_event.get("result"),
                "device_risk": latest_event.get("device_risk") or latest_event.get("ml_risk"),
                "network_risk": latest_event.get("network_risk") or "UNKNOWN",
                "final_risk": latest_event.get("final_risk") or latest_event.get("agent_risk"),
                "action": latest_event.get("action_taken"),
            } if latest_event else None),
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@auth_bp.post("/api/door/lock")
@auth_bp.post("/door/lock")
def api_lock_door():
    """Manually locks simulated door."""
    try:
        res = lock_door()
        return jsonify(res), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@auth_bp.post("/api/door/unlock")
@auth_bp.post("/door/unlock")
def api_unlock_door():
    """Legacy/direct unlock endpoint compatible with existing UI & automated tests."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        password = str(body.get("password", "")).strip()
        if password:
            return public_authenticate()
        
        # Override unlock
        res = unlock_door()
        return jsonify(res), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
