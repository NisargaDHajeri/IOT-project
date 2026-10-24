"""Isolated tests for public assessment-only offline CSV analysis."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from flask import Flask

import database
from config import PROJECT_ROOT
from routes import owner_routes
from services.ciciot_classifier import NETWORK_FEATURE_COLUMNS, reset_model_cache


RAW_DATA = PROJECT_ROOT / "ciciot_experiment" / "data" / "raw"


def csv_row(filename, row_number):
    frame = pd.read_csv(RAW_DATA / filename, nrows=row_number, low_memory=False)
    return {
        name: float(frame.iloc[row_number - 1][name])
        for name in NETWORK_FEATURE_COLUMNS
    }


class TestOfflineAssessmentOnly(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_patch = patch.object(
            database,
            "DATABASE_PATH",
            Path(self.temp_dir.name) / "offline-assessment-test.db",
        )
        self.database_patch.start()
        database.init_db()

        self.app = Flask(__name__)
        self.app.register_blueprint(owner_routes.owner_bp)
        self.client = self.app.test_client()
        self.lockout_patch = patch.object(
            owner_routes, "set_system_lockout", side_effect=AssertionError
        )
        self.door_patch = patch.object(
            owner_routes, "set_door_state", side_effect=AssertionError
        )
        self.command_patch = patch.object(
            owner_routes, "queue_command", side_effect=AssertionError
        )
        self.lockout_patch.start()
        self.door_patch.start()
        self.command_patch.start()
        reset_model_cache()

    def tearDown(self):
        reset_model_cache()
        self.command_patch.stop()
        self.door_patch.stop()
        self.lockout_patch.stop()
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def test_low_medium_high_predictions_persist_without_door_actions(self):
        samples = (
            ("BenignTraffic.pcap.csv", 106, "LOW", "BenignTraffic"),
            ("BenignTraffic.pcap.csv", 13, "MEDIUM", "DictionaryBruteForce"),
            ("DDoS-SYN_Flood.pcap.csv", 1, "HIGH", "DDoS_SYN_Flood"),
        )
        for filename, row_number, expected_risk, expected_attack in samples:
            with self.subTest(risk=expected_risk):
                response = self.client.post(
                    "/api/network/assess-offline",
                    json={"network_features": csv_row(filename, row_number)},
                )
                self.assertEqual(response.status_code, 200, response.get_json())
                result = response.get_json()
                self.assertEqual(result["network_risk"], expected_risk)
                self.assertEqual(result["final_risk"], expected_risk)
                self.assertEqual(
                    result["network_prediction"]["predicted_attack"],
                    expected_attack,
                )
                self.assertEqual(
                    result["assessment_type"],
                    "OFFLINE_SUPPLIED_CSV_ASSESSMENT",
                )
                self.assertFalse(result["live_network_capture"])
                self.assertEqual(
                    result["action_execution_status"],
                    "ASSESSMENT_ONLY_NO_DOOR_ACTION",
                )
                self.assertIsNone(result["hardware_command"])
                self.assertFalse(result["hardware_command_requires_acknowledgement"])

                history_response = self.client.get("/api/network/assessments?limit=10")
                self.assertEqual(history_response.status_code, 200)
                history = history_response.get_json()
                self.assertEqual(history[0]["decision_id"], result["decision_id"])
                self.assertEqual(history[0]["final_risk"], expected_risk)
                self.assertEqual(
                    history[0]["assessment_source"],
                    "SUPPLIED_FLOW_FEATURES",
                )
                self.assertEqual(history[0]["timestamp"], result["timestamp"])

        conn = database.get_db_connection()
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0],
            0,
        )
        door_state = conn.execute(
            "SELECT config_val FROM system_config WHERE config_key = 'simulated_door_state'"
        ).fetchone()["config_val"]
        lockout_until = conn.execute(
            "SELECT config_val FROM system_config WHERE config_key = 'lockout_until'"
        ).fetchone()["config_val"]
        conn.close()
        self.assertEqual(door_state, "LOCKED")
        self.assertFalse(lockout_until)

    def test_owner_only_analysis_route_remains_protected(self):
        response = self.client.post(
            "/api/network/analyze",
            json={"network_features": csv_row("BenignTraffic.pcap.csv", 106)},
        )
        self.assertEqual(response.status_code, 401)

    def test_public_assessment_endpoint_rejects_invalid_feature_schema(self):
        response = self.client.post(
            "/api/network/assess-offline",
            json={"network_features": {"Rate": 1.0}},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
