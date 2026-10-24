"""Automated Unit and Integration Tests for Hardware Pipeline, Google Sheets Bridge,
LangGraph Agent, and Adaptive PQC System.
"""

import sys
import unittest
import hashlib
import time
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.door_auth import (
    authenticate,
    authenticate_hash,
    record_event,
    list_events,
    get_device_status,
    update_device_status,
)
from services.google_sheets_bridge import GoogleSheetsBridge
from services.pqc_profiles import profile_for_risk
from agent import analyze


class TestHardwarePipeline(unittest.TestCase):

    def setUp(self):
        self.bridge = GoogleSheetsBridge()

    def test_01_pin_hashing_and_auth(self):
        """Test SHA-256 hash matching for authorized and unauthorized credentials."""
        dad_hash = hashlib.sha256(b"1234").hexdigest()
        mom_hash = hashlib.sha256(b"5678").hexdigest()
        bad_hash = hashlib.sha256(b"9999").hexdigest()

        dad_auth = authenticate_hash(dad_hash)
        self.assertTrue(dad_auth["success"])
        self.assertEqual(dad_auth["user"], "DAD")

        mom_auth = authenticate_hash(mom_hash)
        self.assertTrue(mom_auth["success"])
        self.assertEqual(mom_auth["user"], "MOM")

        bad_auth = authenticate_hash(bad_hash)
        self.assertFalse(bad_auth["success"])
        self.assertEqual(bad_auth["user"], "UNKNOWN")

    def test_02_pqc_profile_selection(self):
        """Test deterministic mapping of risk levels to NIST PQC algorithms."""
        p_low = profile_for_risk("LOW")
        self.assertEqual(p_low["kem"], "ML-KEM-512")
        self.assertEqual(p_low["signature"], "ML-DSA-44")

        p_med = profile_for_risk("MEDIUM")
        self.assertEqual(p_med["kem"], "ML-KEM-768")
        self.assertEqual(p_med["signature"], "ML-DSA-65")

        p_high = profile_for_risk("HIGH")
        self.assertEqual(p_high["kem"], "ML-KEM-1024")
        self.assertEqual(p_high["signature"], "ML-DSA-87")

    def test_03_hardware_event_processing_success(self):
        """Test end-to-end processing of a valid hardware authentication event."""
        unique_event_id = f"TEST-SUCCESS-{int(time.time() * 1000)}"
        event_data = {
            "device_id": "DOOR-001",
            "event_id": unique_event_id,
            "pin_attempt_hash": hashlib.sha256(b"1234").hexdigest(),
            "timestamp": "2026-09-02T16:00:00+05:30",
        }

        result = self.bridge.process_hardware_event(event_data)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["decision"]["authentication_result"], "SUCCESS")
        self.assertEqual(result["decision"]["user"], "DAD")
        self.assertEqual(result["command"]["command"], "AUTHENTICATION_SUCCESS")

    def test_04_hardware_event_processing_failure_and_escalation(self):
        """Test processing of invalid hardware attempts and risk escalation."""
        unique_event_id = f"TEST-FAIL-{int(time.time() * 1000)}"
        event_data = {
            "device_id": "DOOR-001",
            "event_id": unique_event_id,
            "pin_attempt_hash": hashlib.sha256(b"0000").hexdigest(),
            "timestamp": "2026-09-02T16:00:00+05:30",
        }

        result = self.bridge.process_hardware_event(event_data)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["decision"]["authentication_result"], "FAILED")
        self.assertIn(result["command"]["command"], ["AUTHENTICATION_FAILURE", "INCREASE_MONITORING", "LOCK_AUTHENTICATION"])

    def test_05_idempotency_and_duplicate_prevention(self):
        """Test that duplicate hardware events are skipped safely without re-processing."""
        event_id = f"TEST-DUP-{int(time.time() * 1000)}"
        event_data = {
            "device_id": "DOOR-001",
            "event_id": event_id,
            "pin_attempt_hash": hashlib.sha256(b"1234").hexdigest(),
        }

        first_pass = self.bridge.process_hardware_event(event_data)
        self.assertEqual(first_pass["status"], "SUCCESS")

        second_pass = self.bridge.process_hardware_event(event_data)
        self.assertEqual(second_pass["status"], "SKIPPED_DUPLICATE")

    def test_06_device_status_management(self):
        """Test device telemetry status updates and retrieval."""
        update_device_status({
            "device_id": "DOOR-001",
            "wifi_status": "CONNECTED",
            "ip_address": "192.168.1.105",
            "rssi": -58,
            "firmware_version": "1.0.0",
            "uptime": 1240,
            "device_state": "LOCKED",
        })

        status = get_device_status()
        self.assertEqual(status["device_id"], "DOOR-001")
        self.assertEqual(status["wifi_status"], "CONNECTED")
        self.assertEqual(status["ip_address"], "192.168.1.105")
        self.assertEqual(status["rssi"], -58)
        self.assertTrue(status["is_online"])

    def test_07_langgraph_agent_deterministic_cycle(self):
        """Test LangGraph 8-step deterministic cycle with security context."""
        context = {
            "battery_level": 85,
            "cpu_utilization": 30,
            "memory_usage": 35,
            "failed_auth_attempts": 0,
            "successful_auth_attempts": 1,
            "communication_latency_ms": 35,
            "network_anomaly": 0,
            "threat_indicator": 0,
        }
        res = analyze(context)
        self.assertIn("agent_cycle", res)
        self.assertEqual(res["risk_level"], "LOW")
    def test_08_valid_pin_5678_mom(self):
        """Test authentication with Mom's credential (5678)."""
        mom_hash = hashlib.sha256(b"5678").hexdigest()
        event_id = f"TEST-MOM-{int(time.time() * 1000)}"
        event_data = {
            "device_id": "DOOR-001",
            "event_id": event_id,
            "pin_attempt_hash": mom_hash,
            "timestamp": "2026-09-02T16:00:00+05:30",
        }
        res = self.bridge.process_hardware_event(event_data)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["decision"]["user"], "MOM")
        self.assertEqual(res["decision"]["authentication_result"], "SUCCESS")
        self.assertEqual(res["command"]["command"], "AUTHENTICATION_SUCCESS")

    def test_09_repeated_failures_escalate_to_high_risk_and_lockout(self):
        """Test consecutive failed attempts escalating to HIGH risk and lockout."""
        for i in range(5):
            unique_id = f"TEST-BRUTE-{i}-{int(time.time() * 1000)}"
            event_data = {
                "device_id": "DOOR-001",
                "event_id": unique_id,
                "pin_attempt_hash": hashlib.sha256(f"bad_{i}".encode()).hexdigest(),
                "timestamp": "2026-09-02T16:00:00+05:30",
            }
            res = self.bridge.process_hardware_event(event_data)
        
        # After 5+ failed attempts, final risk must be HIGH and command must be LOCK_AUTHENTICATION
        self.assertEqual(res["decision"]["agent_risk"], "HIGH")
        self.assertEqual(res["command"]["command"], "LOCK_AUTHENTICATION")
        self.assertEqual(res["decision"]["pqc_kem"], "ML-KEM-1024")
        self.assertEqual(res["decision"]["pqc_signature"], "ML-DSA-87")

    def test_10_no_plaintext_pin_in_events(self):
        """Ensure security events log never stores raw plaintext PINs."""
        events = list_events(20)
        for ev in events:
            # pin_attempt_hash must be present and sha256 formatted if source is ESP8266
            if ev.get("source") == "ESP8266_KEYPAD":
                self.assertNotEqual(ev.get("pin_attempt_hash"), "1234")
                self.assertNotEqual(ev.get("pin_attempt_hash"), "5678")
                self.assertNotEqual(ev.get("pin_attempt_hash"), "9999")

    def test_11_flask_endpoints(self):
        """Test all Flask backend endpoints via test client."""
        from app import app
        client = app.test_client()

        # /health
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

        # /api/device/status
        r = client.get("/api/device/status")
        self.assertEqual(r.status_code, 200)

        # /api/device/events
        r = client.get("/api/device/events")
        self.assertEqual(r.status_code, 200)

        # /pqc-test
        r = client.get("/pqc-test?profile=HIGH")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["kem_algorithm"], "ML-KEM-1024")


if __name__ == "__main__":
    unittest.main()
