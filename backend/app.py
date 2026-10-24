"""Master Flask Application for Agentic AI Adaptive PQC Smart Door Lock.

Integrates:
- SQLite Local Relational Persistence
- Random Forest ML Risk Classifier
- 8-Node LangGraph Autonomous Security Agent
- Adaptive NIST Post-Quantum Cryptographic Engine
- Dual Dashboard Delivery (/door and /owner)
- NodeMCU ESP8266 Hardware Telemetry
- AABB Multi-Step Password Reset & Cryptographic OTP Service
"""

import os
from pathlib import Path
from flask import Flask, jsonify
from flask_cors import CORS
from config import FRONTEND_DIR, BASE_DIR
from database import init_db

# Initialize database schema and default seeds
init_db()

# Create Flask Application
app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR),
    static_url_path="",
)
CORS(app)

# Register Modular Blueprints
from routes.auth_routes import auth_bp
from routes.owner_routes import owner_bp
from routes.device_routes import device_bp
from routes.reset_routes import reset_bp
from routes.dashboard_routes import dashboard_bp

app.register_blueprint(auth_bp)
app.register_blueprint(owner_bp)
app.register_blueprint(device_bp)
app.register_blueprint(reset_bp)
app.register_blueprint(dashboard_bp)


def _read_lan_ip_from_file():
    ip_file = BASE_DIR.parent / "ip" / "ipfile"
    if not ip_file.exists():
        return ""
    for line in ip_file.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith(("http://", "https://")):
            value = value.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        return value
    return ""


# Global Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource Not Found", "status": 404}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal Server Error", "status": 500}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("FLASK_PORT", 5000)))
    backend_url = os.environ.get("FLASK_BACKEND_URL") or os.environ.get("DEVICE_API_BASE_URL", "")
    lan_ip = _read_lan_ip_from_file() or os.environ.get("FLASK_LAN_IP", "")
    if not lan_ip and backend_url.startswith("http://"):
        lan_ip = backend_url.removeprefix("http://").split(":", 1)[0]
    lan_ip = lan_ip or "127.0.0.1"
    print("=" * 70)
    print("  AGENTIC AI ADAPTIVE POST-QUANTUM SMART DOOR LOCK (MAJOR PROJECT)")
    print(f"  Local Access          : http://127.0.0.1:{port}")
    print(f"  LAN Access            : http://{lan_ip}:{port}")
    print(f"  Public Door Dashboard : http://{lan_ip}:{port}/door")
    print(f"  Owner Security Console: http://{lan_ip}:{port}/owner")
    print(f"  NodeMCU ESP8266 API   : http://{lan_ip}:{port}/api/device/*")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=False)
