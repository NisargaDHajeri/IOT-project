"""Web Interface & Static Asset Delivery Routes."""

from pathlib import Path
from flask import Blueprint, send_from_directory, redirect, jsonify
from config import FRONTEND_DIR

dashboard_bp = Blueprint("dashboard_bp", __name__)

DOOR_DIR = FRONTEND_DIR / "door"
OWNER_DIR = FRONTEND_DIR / "owner"
SHARED_DIR = FRONTEND_DIR / "shared"


@dashboard_bp.get("/")
def root_index():
    """Root route automatically delivers the Public Locked Door Dashboard."""
    if (DOOR_DIR / "index.html").exists():
        return send_from_directory(str(DOOR_DIR), "index.html")
    return redirect("/door")


@dashboard_bp.get("/door")
def door_dashboard():
    """Renders the Public Locked Door Dashboard."""
    return send_from_directory(str(DOOR_DIR), "index.html")


@dashboard_bp.get("/door/<path:filename>")
def door_static(filename):
    """Serves static CSS/JS for door dashboard."""
    return send_from_directory(str(DOOR_DIR), filename)


@dashboard_bp.get("/owner")
def owner_dashboard():
    """Renders the Owner Security Console."""
    return send_from_directory(str(OWNER_DIR), "index.html")


@dashboard_bp.get("/owner/<path:filename>")
def owner_static(filename):
    """Serves static CSS/JS for owner dashboard."""
    return send_from_directory(str(OWNER_DIR), filename)


@dashboard_bp.get("/shared/<path:filename>")
def shared_static(filename):
    """Serves shared CSS/JS/assets."""
    return send_from_directory(str(SHARED_DIR), filename)


@dashboard_bp.get("/health")
def health_check():
    """System health endpoint."""
    return jsonify({
        "status": "ok",
        "service": "Agentic AI Adaptive PQC Smart Door Security Engine",
        "version": "2.0.0-MAJOR-PROJECT",
    }), 200


@dashboard_bp.get("/api/device/events")
def device_events_alias():
    """Events stream alias for devices."""
    from services.authentication_service import list_recent_events
    return jsonify(list_recent_events(50)), 200


@dashboard_bp.get("/pqc-test")
def pqc_test_endpoint():
    """PQC algorithm benchmark test endpoint."""
    from flask import request
    from services.pqc_service import execute_pqc_operation
    profile = request.args.get("profile", "LOW").upper()
    return jsonify(execute_pqc_operation(profile)), 200

