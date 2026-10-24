"""Authenticated direct REST endpoints for the ESP8266 hardware node."""

import hashlib
import secrets
from functools import wraps
from flask import Blueprint, request, jsonify
from config import DEVICE_ID, DEVICE_SECRET
from services.authentication_service import authenticate_access
from services.device_service import update_device_heartbeat, get_device_status
from services.command_service import get_pending_commands, acknowledge_command
from services.otp_service import trigger_aabb_reset, verify_reset_otp, complete_password_reset_hash

device_bp = Blueprint("device_bp", __name__)
_KEYPAD_ACTIONS = {"INPUT", "CLEAR", "SUBMIT", "IDLE"}


def _device_request(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        token = request.headers.get("X-Device-Token", "")
        if not token or not secrets.compare_digest(token, DEVICE_SECRET):
            return jsonify({"error": "unauthorized device"}), 401
        body = request.get_json(silent=True) or {}
        device_id = str(body.get("device_id") or request.args.get("device_id") or DEVICE_ID).strip()
        if device_id != DEVICE_ID:
            return jsonify({"error": "unknown device"}), 403
        return handler(*args, **kwargs)
    return wrapped


def _telemetry(body):
    return {
        "device_id": DEVICE_ID,
        "ip_address": str(body.get("ip_address") or request.remote_addr or "—"),
        "rssi": int(body.get("rssi", 0)),
        "wifi_status": str(body.get("wifi_status", "CONNECTED")),
        "device_state": str(body.get("device_state", "LOCKED")),
    }


@device_bp.post("/api/device/heartbeat")
@_device_request
def device_heartbeat():
    body = request.get_json(silent=True) or {}
    status = update_device_heartbeat(
        **_telemetry(body),
        input_length=body.get("input_length"),
        keypad_state=body.get("keypad_state"),
    )
    return jsonify({"status": "OK", "device": status}), 200


@device_bp.post("/api/device/keypad-activity")
@_device_request
def device_keypad_activity():
    body = request.get_json(silent=True) or {}
    try:
        input_length = int(body["input_length"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "input_length is required"}), 400
    action = str(body.get("keypad_state", "")).upper()
    if not 0 <= input_length <= 8 or action not in _KEYPAD_ACTIONS:
        return jsonify({"error": "invalid masked keypad activity"}), 400
    status = update_device_heartbeat(**_telemetry(body), input_length=input_length, keypad_state=action)
    return jsonify({"status": "OK", "device": status}), 200


@device_bp.post("/api/device/authenticate")
@_device_request
def device_authenticate():
    body = request.get_json(silent=True) or {}
    if "network_features" in body:
        return jsonify({
            "error": "Network telemetry must use the owner network-analysis API; "
            "it is not accepted as door-authentication evidence."
        }), 400
    pin_hash = str(body.get("pin_hash", "")).lower()
    if len(pin_hash) != 64 or any(c not in "0123456789abcdef" for c in pin_hash):
        return jsonify({"error": "a SHA-256 PIN hash is required"}), 400
    update_device_heartbeat(**_telemetry(body), input_length=0, keypad_state="SUBMIT")
    return jsonify(authenticate_access(pin_hash, source="ESP8266_KEYPAD", is_hash=True, device_id=DEVICE_ID)), 200


@device_bp.get("/api/device/commands")
@_device_request
def device_get_commands():
    commands = get_pending_commands(DEVICE_ID)
    return jsonify({"commands": commands, "count": len(commands)}), 200


@device_bp.post("/api/device/commands/<command_id>/ack")
@_device_request
def device_ack_command(command_id):
    if not command_id.startswith("CMD-"):
        return jsonify({"error": "invalid command id"}), 400
    return jsonify({"success": acknowledge_command(command_id, DEVICE_ID), "command_id": command_id}), 200


@device_bp.post("/api/device/reset/request")
@_device_request
def device_reset_request():
    return jsonify(trigger_aabb_reset(DEVICE_ID)), 200


@device_bp.post("/api/device/reset/verify-otp")
@_device_request
def device_verify_otp():
    otp = str((request.get_json(silent=True) or {}).get("otp", "")).strip()
    success, message = verify_reset_otp(DEVICE_ID, otp)
    return jsonify({"success": success, "message": message}), 200 if success else 400


@device_bp.post("/api/device/reset/set-password")
@_device_request
def device_set_password():
    body = request.get_json(silent=True) or {}
    success, message = complete_password_reset_hash(
        DEVICE_ID, str(body.get("new_pin_hash", "")).lower(), str(body.get("confirm_pin_hash", "")).lower()
    )
    return jsonify({"success": success, "message": message, "door_state": "LOCKED"}), 200 if success else 400


@device_bp.get("/api/device/status")
def device_status_route():
    return jsonify(get_device_status(request.args.get("device_id", DEVICE_ID))), 200
