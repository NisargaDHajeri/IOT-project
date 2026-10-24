"""Owner Security Console & Administrative Routes."""

import logging
import atexit

from flask import Blueprint, request, jsonify, make_response
from functools import wraps
from services.owner_auth_service import (
    authenticate_owner,
    verify_owner_session,
    revoke_owner_session,
    register_owner,
)
from services.authentication_service import list_recent_events
from services.agent_service import (
    AgentPersistenceError,
    analyze_security_context,
    record_action_execution,
)
from services.audit_service import get_security_events, get_audit_logs, log_audit
from services.pqc_service import get_pqc_system_status, get_pqc_profile, execute_pqc_operation
from services.device_service import get_device_status
from services.password_service import get_active_credential_info
from services.risk_engine import get_failed_attempts_count, is_system_locked_out
from services.risk_engine import (
    build_security_context,
    set_system_lockout,
)
from services.simulation_service import get_door_state, set_door_state
from services.command_service import queue_command
from services.ciciot_classifier import validate_network_features
from services.live_network_capture import (
    CaptureBusy,
    CaptureUnavailable,
    live_network_capture,
)
from database import get_db_connection
from config import DEVICE_ID

owner_bp = Blueprint("owner_bp", __name__)
logger = logging.getLogger(__name__)
atexit.register(live_network_capture.stop)


def owner_required(f):
    """Decorator requiring a valid owner session token via cookie or Authorization header."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("owner_session") or request.headers.get("X-Owner-Token")
        username = verify_owner_session(token)
        if not username:
            return jsonify({"error": "Unauthorized. Owner login session required."}), 401
        request.owner_username = username
        return f(*args, **kwargs)
    return decorated_function


@owner_bp.post("/api/owner/login")
def owner_login():
    """Authenticates owner credentials and returns a secure session."""
    try:
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()

        success, token, msg = authenticate_owner(username, password)
        if not success:
            return jsonify({"success": False, "error": msg}), 401

        log_audit(username, "OWNER_LOGIN_SUCCESS", "OWNER_PORTAL", "Owner authenticated to security console.")

        resp = make_response(jsonify({
            "success": True,
            "username": username,
            "token": token,
            "message": "Login successful.",
        }))
        # Set HttpOnly cookie
        resp.set_cookie(
            "owner_session",
            token,
            max_age=86400,
            httponly=True,
            samesite="Lax",
        )
        return resp, 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@owner_bp.post("/api/owner/logout")
def owner_logout():
    """Revokes active owner session and clears session cookie."""
    token = request.cookies.get("owner_session") or request.headers.get("X-Owner-Token")
    if token:
        username = verify_owner_session(token)
        revoke_owner_session(token)
        if username:
            log_audit(username, "OWNER_LOGOUT", "OWNER_PORTAL", "Owner logged out.")

    resp = make_response(jsonify({"success": True, "message": "Logged out successfully."}))
    resp.set_cookie("owner_session", "", max_age=0)
    return resp, 200


@owner_bp.get("/api/owner/status")
def owner_session_status():
    """Checks whether the current client holds an authenticated owner session."""
    token = request.cookies.get("owner_session") or request.headers.get("X-Owner-Token")
    username = verify_owner_session(token)
    if username:
        return jsonify({"authenticated": True, "username": username}), 200
    return jsonify({"authenticated": False, "username": None}), 200


@owner_bp.get("/api/owner/events")
@owner_bp.get("/admin/events")
def owner_events():
    """Fetches recent authentication and security audit events."""
    try:
        limit = request.args.get("limit", 50, type=int)
        auth_events = list_recent_events(limit)
        sec_events = get_security_events(limit)
        return jsonify({
            "events": auth_events,
            "security_events": sec_events,
            "count": len(auth_events),
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@owner_bp.get("/api/owner/analytics")
@owner_required
def owner_analytics():
    """Provides aggregated risk and security analytics for visualization."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Count total, successful, failed attempts
        cursor.execute("SELECT COUNT(*) as total FROM authentication_events;")
        total_attempts = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as successes FROM authentication_events WHERE result = 'SUCCESS';")
        success_count = cursor.fetchone()["successes"]

        cursor.execute("SELECT COUNT(*) as failures FROM authentication_events WHERE result = 'FAILED';")
        failure_count = cursor.fetchone()["failures"]

        # Risk level distribution
        cursor.execute("SELECT agent_risk, COUNT(*) as cnt FROM authentication_events GROUP BY agent_risk;")
        risk_dist = {row["agent_risk"]: row["cnt"] for row in cursor.fetchall()}

        # Recent risk timeline
        cursor.execute(
            """SELECT timestamp, source, user, result, ml_risk, agent_risk, pqc_kem, action_taken
               FROM authentication_events ORDER BY id DESC LIMIT 15;"""
        )
        timeline = [dict(r) for r in cursor.fetchall()]

        conn.close()

        door_state = get_door_state()
        failed_count = get_failed_attempts_count()
        is_locked, remaining_lockout = is_system_locked_out()

        return jsonify({
            "total_attempts": total_attempts,
            "successful_attempts": success_count,
            "failed_attempts": failure_count,
            "active_failed_streak": failed_count,
            "is_locked_out": is_locked,
            "lockout_remaining_seconds": remaining_lockout,
            "door_state": door_state,
            "risk_distribution": {
                "LOW": risk_dist.get("LOW", 0),
                "MEDIUM": risk_dist.get("MEDIUM", 0),
                "HIGH": risk_dist.get("HIGH", 0),
            },
            "timeline": timeline,
            "credential_info": get_active_credential_info(),
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@owner_bp.get("/api/owner/health")
def owner_system_health():
    """Internal system health inspection endpoint."""
    try:
        # Check SQLite DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1;")
        db_ok = (cursor.fetchone() is not None)
        conn.close()
    except Exception:
        db_ok = False

    # Check ML Model
    from services.ml_classifier import MLRiskClassifier
    try:
        m = MLRiskClassifier.get_model()
        ml_ok = (m is not None)
    except Exception:
        ml_ok = False

    # Check PQC
    pqc_status = get_pqc_system_status()
    device_status = get_device_status()

    return jsonify({
        "status": "HEALTHY" if db_ok and ml_ok else "DEGRADED",
        "components": {
            "backend_server": "ONLINE",
            "sqlite_database": "ONLINE" if db_ok else "OFFLINE",
            "random_forest_model": "READY" if ml_ok else "ERROR",
            "langgraph_agent": "READY",
            "pqc_subsystem": "AVAILABLE" if pqc_status["liboqs_available"] else "READY (Profile Dispatcher)",
            "esp8266_hardware": "ONLINE" if device_status.get("is_online") else "OFFLINE",
        },
        "device_telemetry": device_status,
        "pqc_capabilities": pqc_status,
    }), 200


@owner_bp.post("/api/network/analyze")
@owner_required
def analyze_supplied_network_telemetry():
    """Analyze owner-supplied CICIoT flow features; no live capture is active."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 400
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) != {"network_features"}:
        return jsonify({
            "error": "Request must contain exactly one 'network_features' object."
        }), 400

    try:
        features = validate_network_features(body["network_features"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    context = build_security_context(
        failed_count=0,
        source="OWNER_SUPPLIED_NETWORK_ANALYSIS",
        device_id=DEVICE_ID,
    )
    context["network_features"] = features
    context["is_authenticated"] = False

    try:
        result = analyze_security_context(context)
    except FileNotFoundError:
        return jsonify({"error": "Network model or scaler artifact is unavailable."}), 503
    except AgentPersistenceError:
        logger.exception("Could not persist supplied network assessment")
        return jsonify({"error": "Unable to persist the security assessment."}), 500
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Supplied network assessment failed")
        return jsonify({"error": "Network assessment failed."}), 500

    final_risk = result["risk_level"]
    action_status = "NO_DOOR_ACTION"
    queued_command = None
    try:
        if final_risk == "HIGH":
            set_system_lockout()
            set_door_state("LOCKOUT")
            queued_command = queue_command(
                DEVICE_ID,
                "LOCKOUT",
                risk_level="HIGH",
                reason="High risk from owner-supplied network analysis",
            )
            action_status = "LOCKOUT_ACTIVE_COMMAND_PENDING_ACK"
            logger.warning(
                "High-risk supplied network analysis triggered lockout "
                "and queued command %s",
                queued_command["command_id"],
            )
        elif final_risk == "MEDIUM":
            from services.audit_service import log_security_event

            log_security_event(
                severity="MEDIUM",
                event_type="NETWORK_ANALYSIS_MEDIUM_RISK",
                source="OWNER_SUPPLIED_NETWORK_ANALYSIS",
                description="Supplied network flow was assessed at MEDIUM risk.",
            )
            action_status = "MEDIUM_RISK_AUDIT_RECORDED"
        else:
            action_status = "ANALYSIS_RECORDED_NO_DOOR_ACTION"

        record_action_execution(result["decision_id"], action_status)
    except AgentPersistenceError:
        logger.exception("Could not persist network action outcome")
        return jsonify({"error": "Unable to persist the security action outcome."}), 500
    except Exception:
        logger.exception("Network assessment action failed")
        try:
            record_action_execution(
                result["decision_id"], "ACTION_EXECUTION_FAILED"
            )
        except AgentPersistenceError:
            logger.exception("Could not persist failed network action outcome")
        return jsonify({"error": "Network assessment action failed."}), 500

    network_prediction = result.get("network_prediction", {})
    return jsonify({
        "assessment_type": "SUPPLIED_NETWORK_TELEMETRY",
        "live_network_capture": False,
        "decision_id": result["decision_id"],
        "device_risk": result.get("device_risk_level", result["ml_risk_level"]),
        "device_confidence": result.get("ml_risk_confidence", {}),
        "network_risk": result.get("network_risk_level", "UNKNOWN"),
        "network_prediction": network_prediction,
        "network_confidence": network_prediction.get("confidence", {}),
        "final_risk": final_risk,
        "security_profile": result.get("security_profile", {}),
        "agent_reasoning": result.get("reasoning", []),
        "action": result.get("autonomous_action", {}),
        "action_execution_status": action_status,
        "hardware_command": queued_command,
        "hardware_command_requires_acknowledgement": bool(queued_command),
    }), 200


@owner_bp.post("/api/network/assess-offline")
def assess_offline_network_telemetry():
    """Persist a supplied CSV assessment without executing its recommended action."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 400
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) != {"network_features"}:
        return jsonify({
            "error": "Request must contain exactly one 'network_features' object."
        }), 400

    try:
        features = validate_network_features(body["network_features"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    context = build_security_context(
        failed_count=0,
        source="OFFLINE_CSV_ASSESSMENT_ONLY",
        device_id=DEVICE_ID,
    )
    context["network_features"] = features
    context["is_authenticated"] = False

    try:
        result = analyze_security_context(context)
        action_status = "ASSESSMENT_ONLY_NO_DOOR_ACTION"
        record_action_execution(result["decision_id"], action_status)
    except FileNotFoundError:
        return jsonify({"error": "Network model or scaler artifact is unavailable."}), 503
    except AgentPersistenceError:
        logger.exception("Could not persist offline assessment-only network decision")
        return jsonify({"error": "Unable to persist the network assessment."}), 500
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Offline assessment-only network analysis failed")
        return jsonify({"error": "Network assessment failed."}), 500

    network_prediction = result.get("network_prediction", {})
    return jsonify({
        "assessment_type": "OFFLINE_SUPPLIED_CSV_ASSESSMENT",
        "live_network_capture": False,
        "timestamp": result["timestamp"],
        "decision_id": result["decision_id"],
        "device_risk": result.get("device_risk_level", result["ml_risk_level"]),
        "device_confidence": result.get("ml_risk_confidence", {}),
        "network_risk": result.get("network_risk_level", "UNKNOWN"),
        "network_prediction": network_prediction,
        "network_confidence": network_prediction.get("confidence", {}),
        "final_risk": result["risk_level"],
        "security_profile": result.get("security_profile", {}),
        "agent_reasoning": result.get("reasoning", []),
        "action": result.get("autonomous_action", {}),
        "action_execution_status": action_status,
        "hardware_command": None,
        "hardware_command_requires_acknowledgement": False,
    }), 200


@owner_bp.get("/api/owner/network-capture")
@owner_required
def owner_network_capture_status():
    """Return capture state and explicitly enumerated selectable interfaces."""
    return jsonify(live_network_capture.snapshot(include_interfaces=True)), 200


@owner_bp.post("/api/owner/network-capture/start")
@owner_required
def start_owner_network_capture():
    """Start an explicitly selected, bounded, passive metadata capture."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 400
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) != {"interface", "duration_seconds"}:
        return jsonify({
            "error": "Request must contain exactly 'interface' and 'duration_seconds'."
        }), 400
    try:
        status = live_network_capture.start(
            body["interface"],
            body["duration_seconds"],
        )
    except CaptureBusy as exc:
        return jsonify({"error": str(exc)}), 409
    except CaptureUnavailable as exc:
        return jsonify({"error": str(exc)}), 503
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(status), 202


@owner_bp.post("/api/owner/network-capture/stop")
@owner_required
def stop_owner_network_capture():
    """Stop the active capture and flush any complete metadata window."""
    try:
        return jsonify(live_network_capture.stop()), 200
    except CaptureBusy as exc:
        return jsonify({"error": str(exc)}), 409


@owner_bp.get("/api/owner/network-assessments")
@owner_required
def owner_network_assessments():
    """Return recent persisted network assessments to the owner console."""
    try:
        limit = max(1, min(request.args.get("limit", 10, type=int), 50))
        conn = get_db_connection()
        rows = conn.execute(
            """SELECT decision_id, timestamp, device_risk, network_risk,
                      network_prediction_json, network_confidence_json,
                      final_risk, pqc_kem, pqc_sig, action,
                      execution_status, reasoning_json, pqc_execution_mode,
                      device_confidence_json
               FROM agent_decisions
               WHERE network_risk IS NOT NULL AND network_risk != 'UNKNOWN'
               ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        conn.close()
        import json

        assessments = []
        for row in rows:
            prediction = json.loads(row["network_prediction_json"] or "{}")
            assessments.append({
                **dict(row),
                "assessment_source": prediction.get(
                    "assessment_type",
                    prediction.get("telemetry_source", "SUPPLIED_FLOW_FEATURES"),
                ),
                "network_prediction": prediction,
                "network_confidence": json.loads(
                    row["network_confidence_json"] or "{}"
                ),
                "device_confidence": json.loads(
                    row["device_confidence_json"] or "{}"
                ),
                "agent_reasoning": json.loads(row["reasoning_json"] or "[]"),
            })
        return jsonify(assessments), 200
    except Exception:
        logger.exception("Could not load persisted network assessments")
        return jsonify({"error": "Unable to load network assessments."}), 500


@owner_bp.get("/api/network/assessments")
def public_network_assessments():
    """Expose only persisted network-assessment fields for the public door dashboard."""
    try:
        limit = max(1, min(request.args.get("limit", 10, type=int), 50))
        conn = get_db_connection()
        rows = conn.execute(
            """SELECT decision_id, timestamp, device_risk, network_risk,
                      network_prediction_json, network_confidence_json,
                      final_risk, pqc_kem, pqc_sig, execution_status
               FROM agent_decisions
               WHERE network_risk IS NOT NULL AND network_risk != 'UNKNOWN'
               ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        conn.close()
        import json

        assessments = []
        for row in rows:
            prediction = json.loads(row["network_prediction_json"] or "{}")
            assessments.append({
                "decision_id": row["decision_id"],
                "timestamp": row["timestamp"],
                "device_risk": row["device_risk"],
                "network_risk": row["network_risk"],
                "network_prediction": prediction,
                "network_confidence": json.loads(
                    row["network_confidence_json"] or "{}"
                ),
                "final_risk": row["final_risk"],
                "pqc_kem": row["pqc_kem"],
                "pqc_sig": row["pqc_sig"],
                "execution_status": row["execution_status"],
                "assessment_source": prediction.get(
                    "assessment_type",
                    prediction.get("telemetry_source", "SUPPLIED_FLOW_FEATURES"),
                ),
            })
        return jsonify(assessments), 200
    except Exception:
        logger.exception("Could not load public network assessment history")
        return jsonify({"error": "Unable to load network assessments."}), 500
