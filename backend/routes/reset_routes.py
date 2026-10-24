"""Password Reset & OTP Management Routes."""

from flask import Blueprint, request, jsonify
from services.otp_service import (
    create_reset_session,
    trigger_aabb_reset,
    get_active_reset_session,
    verify_reset_otp,
    complete_password_reset,
    complete_password_reset_hash,
    revoke_reset_session,
)
from services.owner_auth_service import verify_owner_session
from services.audit_service import log_security_event, log_audit
from config import DEVICE_ID

reset_bp = Blueprint("reset_bp", __name__)


@reset_bp.post("/api/reset/request")
def reset_request():
    """Initiates password reset sequence (triggered by ESP8266 AABB or web UI)."""
    try:
        body = request.get_json(silent=True) or {}
        device_id = str(body.get("device_id", DEVICE_ID)).strip()
        source = str(body.get("source", "KEYPAD")).strip()

        res = trigger_aabb_reset(device_id)
        log_security_event(
            severity="INFO",
            event_type="PASSWORD_RESET_INITIATED",
            source=source,
            description="Password reset sequence triggered (AABB). Awaiting Owner OTP.",
        )
        return jsonify(res), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@reset_bp.post("/api/reset/generate-otp")
def generate_otp():
    """Generates a cryptographically random 6-digit OTP (2-min expiry).
    
    Can be called by authenticated owner or for hardware demo verification.
    """
    try:
        body = request.get_json(silent=True) or {}
        device_id = str(body.get("device_id", DEVICE_ID)).strip()

        token = request.cookies.get("owner_session") or request.headers.get("X-Owner-Token")
        owner_user = verify_owner_session(token) or "OWNER"

        session = create_reset_session(device_id)
        log_audit(owner_user, "OTP_GENERATED", "OWNER_CONSOLE", f"Generated 6-digit OTP for device {device_id}.")
        log_security_event(
            severity="INFO",
            event_type="RESET_OTP_GENERATED",
            source="OWNER_CONSOLE",
            description=f"6-digit reset OTP generated for session {session['session_id']} (TTL: 120s).",
        )

        return jsonify({
            "success": True,
            "session_id": session["session_id"],
            "device_id": session["device_id"],
            "otp": session["otp"],
            "expires_in_seconds": session["expires_in_seconds"],
            "expires_at": session["expires_at"],
            "status": "ACTIVE",
            "message": "Reset OTP generated. Valid for 2 minutes.",
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@reset_bp.get("/api/reset/status")
def reset_status():
    """Fetches status of the current active reset session with countdown timer."""
    try:
        device_id = request.args.get("device_id", DEVICE_ID)
        session = get_active_reset_session(device_id)

        token = request.cookies.get("owner_session") or request.headers.get("X-Owner-Token")
        is_owner = bool(verify_owner_session(token))

        if not session:
            return jsonify({
                "active_session": False,
                "status": "NONE",
                "remaining_seconds": 0,
                "message": "No active password reset session.",
            }), 200

        resp = {
            "active_session": (session["status"] in ["PENDING", "OTP_VERIFIED"]),
            "session_id": session["session_id"],
            "device_id": session["device_id"],
            "status": session["status"],
            "remaining_seconds": session["remaining_seconds"],
            "attempt_count": session["attempt_count"],
            "max_attempts": session["max_attempts"],
        }
        # Only authenticated owner sees plaintext OTP in status check
        if is_owner and session.get("otp"):
            resp["otp"] = session["otp"]

        return jsonify(resp), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@reset_bp.post("/api/reset/verify-otp")
def verify_otp_endpoint():
    """Verifies entered 6-digit OTP from ESP8266 keypad or Owner dashboard."""
    try:
        body = request.get_json(silent=True) or {}
        device_id = str(body.get("device_id", DEVICE_ID)).strip()
        otp = str(body.get("otp", "")).strip()

        success, msg = verify_reset_otp(device_id, otp)
        if not success:
            log_security_event(
                severity="MEDIUM",
                event_type="RESET_OTP_FAILED",
                source="RESET_VERIFIER",
                description=f"Incorrect or expired OTP submitted: {msg}",
            )
            return jsonify({"success": False, "error": msg}), 400

        log_security_event(
            severity="INFO",
            event_type="RESET_OTP_VERIFIED",
            source="RESET_VERIFIER",
            description="Reset OTP verified successfully. Awaiting new password entry.",
        )
        return jsonify({"success": True, "message": msg, "state": "OTP_VERIFIED"}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@reset_bp.post("/api/reset/set-password")
def set_new_password():
    """Atomically commits new password after OTP verification."""
    try:
        body = request.get_json(silent=True) or {}
        device_id = str(body.get("device_id", DEVICE_ID)).strip()
        new_hash = str(body.get("new_pin_hash", "")).strip().lower()
        confirm_hash = str(body.get("confirm_pin_hash", "")).strip().lower()
        if new_hash or confirm_hash:
            success, msg = complete_password_reset_hash(device_id, new_hash, confirm_hash)
        else:
            new_password = str(body.get("new_password", body.get("new_pin", ""))).strip()
            confirm_password = str(body.get("confirm_password", body.get("confirm_pin", ""))).strip()
            success, msg = complete_password_reset(device_id, new_password, confirm_password)
        if not success:
            return jsonify({"success": False, "error": msg}), 400

        log_security_event(
            severity="INFO",
            event_type="PASSWORD_RESET_COMPLETED",
            source="RESET_CONTROLLER",
            description="Door password reset successfully. Old credential revoked, new version active.",
        )
        log_audit("RESET_FLOW", "PASSWORD_RESET_SUCCESS", "RESET_CONTROLLER", "Door password reset completed.")

        return jsonify({"success": True, "message": msg, "door_state": "LOCKED"}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@reset_bp.post("/api/reset/revoke")
def revoke_reset():
    """Revokes active reset session."""
    try:
        body = request.get_json(silent=True) or {}
        device_id = str(body.get("device_id", DEVICE_ID)).strip()

        success, msg = revoke_reset_session(device_id)
        return jsonify({"success": success, "message": msg}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
