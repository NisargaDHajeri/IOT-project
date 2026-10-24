"""End-to-end tests for combined device and supplied network assessments."""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from app import app
from config import DEVICE_ID, DEVICE_SECRET, PROJECT_ROOT
from database import get_db_connection, init_db
from services.authentication_service import authenticate_access
from services.ciciot_classifier import reset_model_cache
from services.pqc_service import execute_pqc_operation
from services.risk_engine import clear_system_lockout, reset_failed_attempts
from services.simulation_service import set_door_state


RAW_DATA = PROJECT_ROOT / "ciciot_experiment" / "data" / "raw"
FEATURE_COLUMNS = (
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number",
    "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH",
    "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv",
    "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
    "IAT", "Number", "Variance",
)


def representative_row(filename):
    """Use the known representative sample, not an assumed first CSV row."""
    frame = pd.read_csv(RAW_DATA / filename, nrows=106, low_memory=False)
    return {
        name: float(frame.iloc[105][name])
        for name in FEATURE_COLUMNS
    }


class TestNetworkIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = app.test_client()
        cls.benign = representative_row("BenignTraffic.pcap.csv")
        cls.ddos = representative_row("DDoS-SYN_Flood.pcap.csv")
        response = cls.client.post(
            "/api/owner/login",
            json={"username": "admin", "password": "test-owner-password"},
        )
        if response.status_code != 200:
            raise AssertionError("Test owner login could not be initialized.")
        cls.owner_headers = {
            "X-Owner-Token": response.get_json()["token"]
        }

    def setUp(self):
        clear_system_lockout()
        reset_failed_attempts()
        set_door_state("LOCKED")
        conn = get_db_connection()
        for table in (
            "authentication_events",
            "agent_decisions",
            "risk_assessments",
            "commands",
            "security_events",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def tearDown(self):
        clear_system_lockout()
        reset_failed_attempts()
        set_door_state("LOCKED")

    def test_benign_and_ddos_network_predictions_and_persistence(self):
        benign_response = self.client.post(
            "/api/network/analyze",
            json={"network_features": self.benign},
            headers=self.owner_headers,
        )
        self.assertEqual(benign_response.status_code, 200)
        benign = benign_response.get_json()
        self.assertEqual(
            benign["network_prediction"]["predicted_attack"], "BenignTraffic"
        )
        self.assertEqual(benign["network_risk"], "LOW")
        self.assertEqual(benign["final_risk"], "LOW")
        self.assertFalse(benign["live_network_capture"])

        ddos_response = self.client.post(
            "/api/network/analyze",
            json={"network_features": self.ddos},
            headers=self.owner_headers,
        )
        self.assertEqual(ddos_response.status_code, 200)
        ddos = ddos_response.get_json()
        self.assertEqual(
            ddos["network_prediction"]["predicted_attack"], "DDoS_SYN_Flood"
        )
        self.assertEqual(ddos["network_risk"], "HIGH")
        self.assertEqual(ddos["final_risk"], "HIGH")
        self.assertEqual(ddos["security_profile"]["kem"], "ML-KEM-1024")
        self.assertEqual(
            ddos["action_execution_status"],
            "LOCKOUT_ACTIVE_COMMAND_PENDING_ACK",
        )
        self.assertTrue(ddos["hardware_command_requires_acknowledgement"])

        conn = get_db_connection()
        decision = conn.execute(
            """SELECT device_risk, network_risk, network_prediction_json,
                      network_confidence_json, final_risk, pqc_kem, pqc_sig,
                      action, execution_status
               FROM agent_decisions WHERE decision_id = ?""",
            (ddos["decision_id"],),
        ).fetchone()
        self.assertIsNotNone(decision)
        self.assertEqual(decision["network_risk"], "HIGH")
        self.assertEqual(json.loads(decision["network_prediction_json"])["predicted_attack"],
                         "DDoS_SYN_Flood")
        self.assertTrue(json.loads(decision["network_confidence_json"]))
        self.assertEqual(decision["final_risk"], "HIGH")
        self.assertEqual(decision["pqc_kem"], "ML-KEM-1024")
        self.assertEqual(decision["pqc_sig"], "ML-DSA-87")
        self.assertEqual(
            decision["execution_status"],
            "LOCKOUT_ACTIVE_COMMAND_PENDING_ACK",
        )
        command = conn.execute(
            "SELECT command, status FROM commands WHERE command_id = ?",
            (ddos["hardware_command"]["command_id"],),
        ).fetchone()
        self.assertEqual(command["command"], "LOCKOUT")
        self.assertEqual(command["status"], "PENDING")
        conn.close()

    def test_device_only_assessment_reports_network_unavailable(self):
        from services.agent_service import analyze_security_context

        context = {
            "battery_level": 88,
            "cpu_utilization": 20,
            "memory_usage": 25,
            "failed_auth_attempts": 0,
            "successful_auth_attempts": 1,
            "communication_latency_ms": 35,
            "network_anomaly": 0,
            "threat_indicator": 0,
            "is_authenticated": False,
        }
        result = analyze_security_context(context)
        self.assertIn(result["device_risk_level"], {"LOW", "MEDIUM", "HIGH"})
        self.assertEqual(result["network_risk_level"], "UNKNOWN")
        self.assertEqual(result["network_prediction"], {})
        self.assertFalse(result["reflection"]["network_model_executed"])

    def test_high_device_risk_is_not_erased_by_benign_network(self):
        from services.agent_service import analyze_security_context

        context = {
            "battery_level": 88,
            "cpu_utilization": 20,
            "memory_usage": 25,
            "failed_auth_attempts": 0,
            "successful_auth_attempts": 1,
            "communication_latency_ms": 35,
            "network_anomaly": 0,
            "threat_indicator": 0,
            "network_features": self.benign,
            "is_authenticated": False,
        }
        high_device_result = {
            "predicted_risk": "HIGH",
            "confidence": {"LOW": 0.0, "MEDIUM": 0.01, "HIGH": 0.99},
            "max_confidence": 0.99,
        }
        with patch(
            "agent.security_agent.predict_risk",
            return_value=high_device_result,
        ):
            result = analyze_security_context(context)
        self.assertEqual(result["device_risk_level"], "HIGH")
        self.assertEqual(result["network_risk_level"], "LOW")
        self.assertEqual(result["risk_level"], "HIGH")

    def test_network_api_validation_and_owner_access(self):
        no_auth = app.test_client().post(
            "/api/network/analyze",
            json={"network_features": self.benign},
        )
        self.assertEqual(no_auth.status_code, 401)

        missing = dict(self.benign)
        missing.pop("Rate")
        response = self.client.post(
            "/api/network/analyze",
            json={"network_features": missing},
            headers=self.owner_headers,
        )
        self.assertEqual(response.status_code, 400)

        extra = {**self.benign, "not_a_feature": 1.0}
        response = self.client.post(
            "/api/network/analyze",
            json={"network_features": extra},
            headers=self.owner_headers,
        )
        self.assertEqual(response.status_code, 400)

        nonfinite = dict(self.benign)
        for invalid_value in (float("nan"), float("inf"), "not-numeric"):
            nonfinite = dict(self.benign)
            nonfinite["Rate"] = invalid_value
            response = self.client.post(
                "/api/network/analyze",
                data=json.dumps({"network_features": nonfinite}),
                content_type="application/json",
                headers=self.owner_headers,
            )
            self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/api/network/analyze",
            data="not-json",
            content_type="application/json",
            headers=self.owner_headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_missing_model_or_scaler_returns_service_unavailable(self):
        from services import ciciot_classifier

        for artifact in ("MODEL_PATH", "SCALER_PATH"):
            reset_model_cache()
            with patch.object(
                ciciot_classifier,
                artifact,
                Path(f"missing-test-network-{artifact.lower()}.pkl"),
            ):
                response = self.client.post(
                    "/api/network/analyze",
                    json={"network_features": self.benign},
                    headers=self.owner_headers,
                )
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("traceback", response.get_data(as_text=True).lower())
        reset_model_cache()

    def test_authentication_and_high_risk_denial_actions(self):
        good = self.client.post(
            "/api/authenticate",
            json={"password": "1234"},
        )
        self.assertEqual(good.status_code, 200)
        good_data = good.get_json()
        self.assertTrue(good_data["authenticated"])
        self.assertTrue(good_data["credential_verified"])
        self.assertEqual(good_data["door_state"], "OPEN")

        from agent import security_agent

        high_device_result = {
            "predicted_risk": "HIGH",
            "confidence": {"LOW": 0.0, "MEDIUM": 0.0, "HIGH": 1.0},
            "max_confidence": 1.0,
        }
        with patch.object(
            security_agent, "predict_risk", return_value=high_device_result
        ):
            denied = authenticate_access("9999")
        self.assertFalse(denied["authenticated"])
        self.assertFalse(denied["credential_verified"])
        self.assertEqual(denied["door_state"], "LOCKOUT")
        self.assertEqual(
            denied["action_execution_status"],
            "LOCKOUT_ACTIVE_COMMAND_PENDING_ACK",
        )

        conn = get_db_connection()
        event = conn.execute(
            """SELECT result, agent_risk, action_taken, decision_id
               FROM authentication_events ORDER BY id DESC LIMIT 1"""
        ).fetchone()
        self.assertEqual(event["result"], "FAILED")
        self.assertEqual(event["agent_risk"], "HIGH")
        self.assertTrue(event["decision_id"])
        command = conn.execute(
            """SELECT command, status FROM commands
               WHERE command = 'LOCKOUT' ORDER BY id DESC LIMIT 1"""
        ).fetchone()
        self.assertEqual(command["status"], "PENDING")
        conn.close()

    def test_existing_device_security_and_dashboard_routes(self):
        missing_token = self.client.post(
            "/api/device/heartbeat",
            json={"device_id": DEVICE_ID},
        )
        self.assertEqual(missing_token.status_code, 401)

        attempted_feature_injection = self.client.post(
            "/api/device/authenticate",
            json={
                "device_id": DEVICE_ID,
                "pin_hash": hashlib.sha256(b"1234").hexdigest(),
                "network_features": self.ddos,
            },
            headers={"X-Device-Token": DEVICE_SECRET},
        )
        self.assertEqual(attempted_feature_injection.status_code, 400)

        door_response = self.client.get("/door")
        owner_response = self.client.get("/owner")
        self.assertEqual(door_response.status_code, 200)
        self.assertEqual(owner_response.status_code, 200)
        door_response.close()
        owner_response.close()
        assessments = self.client.get(
            "/api/owner/network-assessments",
            headers=self.owner_headers,
        )
        self.assertEqual(assessments.status_code, 200)

    def test_pqc_status_is_honest_about_native_execution(self):
        result = execute_pqc_operation("LOW")
        if result["is_native_pqc"]:
            self.assertEqual(result["status"], "PQC_NATIVE_EXECUTION_SUCCESS")
        else:
            self.assertEqual(result["status"], "PROFILE_SELECTED")
            self.assertEqual(
                result["execution_status"],
                "PROFILE_SELECTION_ONLY (native liboqs unavailable)",
            )
            self.assertNotIn("ciphertext_sample", result)


if __name__ == "__main__":
    unittest.main()
