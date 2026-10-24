"""Isolated tests for shared authentication decisions and network history."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database
from flask import Flask
from routes import auth_routes, owner_routes
from services import authentication_service


class TestSecurityDecisionSync(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_patch = patch.object(
            database,
            "DATABASE_PATH",
            Path(self.temp_dir.name) / "decision-sync-test.db",
        )
        self.database_patch.start()
        database.init_db()
        self.app = Flask(__name__)
        self.app.register_blueprint(owner_routes.owner_bp)
        self.app.register_blueprint(auth_routes.auth_bp)
        self.client = self.app.test_client()
        self.owner_patch = patch.object(
            owner_routes, "verify_owner_session", return_value="test-owner"
        )
        self.owner_patch.start()

    def tearDown(self):
        self.owner_patch.stop()
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def _record_decision(self, decision_id, risk):
        conn = database.get_db_connection()
        conn.execute(
            """INSERT INTO agent_decisions (
                decision_id, timestamp, ml_risk, final_risk, escalation_applied,
                escalation_reason, action, message, execution_status, pqc_kem,
                pqc_sig, reasoning_json, observations_json, device_risk,
                network_risk, network_prediction_json, device_confidence_json,
                network_confidence_json, pqc_execution_mode
            ) VALUES (?, '2026-10-24T10:00:00+00:00', ?, ?, 0, '', ?, '', ?, ?, ?, '[]', '[]', ?, 'UNKNOWN', '{}', '{}', '{}', 'PROFILE_SELECTION_ONLY')""",
            (
                decision_id,
                risk,
                risk,
                "RECORD_FAILED_ATTEMPT",
                "TEST_ASSESSMENT_ONLY",
                "ML-KEM-512",
                "ML-DSA-44",
                risk,
            ),
        )
        conn.commit()
        conn.close()

    def _generate_isolated_failed_auth_event(self, risk):
        decision_id = f"DEC-TEST-{risk}"
        self._record_decision(decision_id, risk)
        agent_result = {
            "decision_id": decision_id,
            "risk_level": risk,
            "ml_risk_level": risk,
            "ml_risk_confidence": {risk: 1.0},
            "network_risk_level": "UNKNOWN",
            "network_prediction": {},
            "security_profile": {"kem": "ML-KEM-512", "signature": "ML-DSA-44"},
            "autonomous_action": {"action": "RECORD_FAILED_ATTEMPT", "message": ""},
            "reasoning": [],
            "observations": [],
            "escalation_applied": False,
            "escalation_reason": "",
        }
        with (
            patch.object(authentication_service, "is_system_locked_out", return_value=(False, 0)),
            patch.object(authentication_service, "verify_door_pin", return_value=(False, None)),
            patch.object(authentication_service, "increment_failed_attempts", return_value=1),
            patch.object(authentication_service, "build_security_context", return_value={}),
            patch.object(authentication_service, "analyze_security_context", return_value=agent_result),
            patch.object(authentication_service, "execute_pqc_operation", return_value={}),
            patch.object(authentication_service, "set_system_lockout"),
            patch.object(authentication_service, "set_door_state", return_value="LOCKED"),
            patch.object(authentication_service, "queue_command", return_value={"command_id": "TEST-NO-HARDWARE"}),
            patch.object(authentication_service, "record_action_execution"),
            patch.object(authentication_service, "log_security_event"),
            patch.object(authentication_service, "log_audit"),
        ):
            return authentication_service.authenticate_access(
                "safe-isolated-invalid-test-value",
                source="WEB_UI",
            )

    def test_authentication_decisions_share_ids_timestamps_risks_and_missing_network(self):
        for risk in ("LOW", "MEDIUM", "HIGH"):
            with self.subTest(risk=risk):
                result = self._generate_isolated_failed_auth_event(risk)
                self.assertFalse(result["authenticated"])
                response = self.client.get("/api/owner/events?limit=10")
                self.assertEqual(response.status_code, 200)
                event = next(
                    item for item in response.get_json()["events"]
                    if item["event_id"] == result["event_id"]
                )
                self.assertEqual(event["decision_id"], result["decision_id"])
                self.assertEqual(event["device_risk"], risk)
                self.assertEqual(event["agent_risk"], risk)
                self.assertEqual(event["final_risk"], risk)
                self.assertEqual(event["network_risk"], "UNKNOWN")
                self.assertEqual(event["source"], "WEB_UI")
                self.assertEqual(event["action_taken"], "RECORD_FAILED_ATTEMPT")
                self.assertTrue(event["timestamp"])
                door_status = self.client.get("/api/door/status")
                self.assertEqual(door_status.status_code, 200)
                latest = door_status.get_json()["latest_security_decision"]
                self.assertEqual(latest["event_id"], result["event_id"])
                self.assertEqual(latest["decision_id"], result["decision_id"])
                self.assertEqual(latest["timestamp"], event["timestamp"])
                self.assertEqual(latest["device_risk"], risk)
                self.assertEqual(latest["final_risk"], risk)
                self.assertEqual(latest["network_risk"], "UNKNOWN")
                self.assertEqual(latest["source"], "WEB_UI")

    def test_network_history_keeps_offline_assessment_separate(self):
        decision_id = "DEC-HISTORIC-CSV"
        prediction = {
            "telemetry_source": "SUPPLIED_FLOW_FEATURES",
            "live_capture": False,
            "predicted_attack": "BenignTraffic",
            "max_confidence": 0.95,
        }
        conn = database.get_db_connection()
        conn.execute(
            """INSERT INTO agent_decisions (
                decision_id, timestamp, ml_risk, final_risk, escalation_applied,
                escalation_reason, action, message, execution_status, pqc_kem,
                pqc_sig, reasoning_json, observations_json, device_risk,
                network_risk, network_prediction_json, device_confidence_json,
                network_confidence_json, pqc_execution_mode
            ) VALUES (?, '2026-10-23T10:00:00+00:00', 'LOW', 'LOW', 0, '', 'ANALYZE', '', 'RECORDED', 'ML-KEM-512', 'ML-DSA-44', '[]', '[]', 'LOW', 'LOW', ?, '{}', '{}', 'PROFILE_SELECTION_ONLY')""",
            (decision_id, json.dumps(prediction)),
        )
        conn.commit()
        conn.close()

        self._generate_isolated_failed_auth_event("MEDIUM")
        response = self.client.get("/api/owner/network-assessments?limit=10")
        self.assertEqual(response.status_code, 200)
        assessments = response.get_json()
        csv_record = next(item for item in assessments if item["decision_id"] == decision_id)
        self.assertEqual(csv_record["assessment_source"], "SUPPLIED_FLOW_FEATURES")
        self.assertEqual(csv_record["network_prediction"]["predicted_attack"], "BenignTraffic")
        self.assertNotIn(
            "DEC-TEST-MEDIUM",
            {item["decision_id"] for item in assessments},
            "Authentication decisions without network evidence must not be exposed as network assessments.",
        )


if __name__ == "__main__":
    unittest.main()
