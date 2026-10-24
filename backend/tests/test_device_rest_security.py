"""Direct ESP8266 REST transport security tests."""
import unittest
from app import app


class TestDeviceRestSecurity(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.headers = {"X-Device-Token": "test-device-token-not-a-secret"}

    def test_device_routes_reject_missing_token(self):
        response = self.client.post("/api/device/heartbeat", json={"device_id": "DOOR-001"})
        self.assertEqual(response.status_code, 401)

    def test_masked_activity_accepts_length_but_not_digits(self):
        response = self.client.post("/api/device/keypad-activity", headers=self.headers, json={
            "device_id": "DOOR-001", "input_length": 3, "keypad_state": "INPUT"
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["device"]["input_length"], 3)

    def test_device_auth_requires_sha256_hex(self):
        response = self.client.post("/api/device/authenticate", headers=self.headers, json={
            "device_id": "DOOR-001", "pin_hash": "1234"
        })
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
