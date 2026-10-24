"""Tests for Physical ESP8266 Keypad -> Masked Input Telemetry Synchronization."""

import unittest
import json
from app import app
from database import init_db, get_db_connection
from services.device_service import update_device_heartbeat, get_device_status
from services.google_sheets_bridge import GoogleSheetsBridge


class TestMaskedKeypadSync(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = app.test_client()

    def test_01_update_and_retrieve_keypad_state(self):
        """Test updating device telemetry with input_length and keypad_state."""
        st1 = update_device_heartbeat(
            device_id="DOOR-001",
            input_length=1,
            keypad_state="INPUT"
        )
        self.assertEqual(st1["input_length"], 1)
        self.assertEqual(st1["keypad_state"], "INPUT")

        st4 = update_device_heartbeat(
            device_id="DOOR-001",
            input_length=4,
            keypad_state="INPUT"
        )
        self.assertEqual(st4["input_length"], 4)
        self.assertEqual(st4["keypad_state"], "INPUT")

        status = get_device_status("DOOR-001")
        self.assertEqual(status["input_length"], 4)
        self.assertEqual(status["keypad_state"], "INPUT")

    def test_02_keypad_clear_action(self):
        """Test that pressing * (CLEAR) resets input_length to 0."""
        update_device_heartbeat(device_id="DOOR-001", input_length=3, keypad_state="INPUT")
        
        st_clear = update_device_heartbeat(device_id="DOOR-001", input_length=0, keypad_state="CLEAR")
        self.assertEqual(st_clear["input_length"], 0)
        self.assertEqual(st_clear["keypad_state"], "CLEAR")

    def test_03_device_status_http_endpoint(self):
        """Test GET /api/device/status returns input_length and keypad_state."""
        update_device_heartbeat(device_id="DOOR-001", input_length=3, keypad_state="INPUT")

        res = self.client.get("/api/device/status?device_id=DOOR-001")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("input_length", data)
        self.assertIn("keypad_state", data)
        self.assertEqual(data["input_length"], 3)
        self.assertEqual(data["keypad_state"], "INPUT")

    def test_04_device_heartbeat_post_endpoint(self):
        """Test POST /api/device/heartbeat receives and updates masked state."""
        payload = {
            "device_id": "DOOR-001",
            "ip_address": "192.168.1.55",
            "rssi": -60,
            "wifi_status": "CONNECTED",
            "device_state": "LOCKED",
            "input_length": 2,
            "keypad_state": "INPUT"
        }
        res = self.client.post("/api/device/heartbeat", json=payload,
                               headers={"X-Device-Token": "test-device-token-not-a-secret"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["device"]["input_length"], 2)
        self.assertEqual(data["device"]["keypad_state"], "INPUT")

    def test_05_auth_attempt_resets_input_length(self):
        """Test that submitting an authentication attempt resets input_length to 0."""
        update_device_heartbeat(device_id="DOOR-001", input_length=4, keypad_state="INPUT")

        res = self.client.post("/api/device/authenticate", json={
            "device_id": "DOOR-001",
            "pin_hash": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
            "is_hash": True,
        }, headers={"X-Device-Token": "test-device-token-not-a-secret"})
        self.assertEqual(res.status_code, 200)

        status = get_device_status("DOOR-001")
        self.assertEqual(status["input_length"], 0)
        self.assertEqual(status["keypad_state"], "SUBMIT")

    def test_06_zero_raw_pin_exposed(self):
        """Ensure device status never contains plaintext digit fields or secrets."""
        status = get_device_status("DOOR-001")
        for key in ["pin", "password", "raw_pin", "digits", "secret"]:
            self.assertNotIn(key, status)


if __name__ == "__main__":
    unittest.main()
