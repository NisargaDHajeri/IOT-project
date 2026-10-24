"""Integration Test Suite for Flask REST API Endpoints & Dual Dashboards."""

import unittest
import json
from app import app
from database import init_db, get_db_connection
from services.risk_engine import clear_system_lockout, reset_failed_attempts
from services.password_service import update_door_pin


class TestApiEndpoints(unittest.TestCase):

    def setUp(self):
        init_db()
        self.client = app.test_client()
        clear_system_lockout()
        reset_failed_attempts()
        update_door_pin("1234", user_alias="DAD")
        
        # Clear test transient events for clean test isolation
        conn = get_db_connection()
        conn.execute("DELETE FROM authentication_events;")
        conn.execute("DELETE FROM reset_sessions;")
        conn.execute("DELETE FROM commands;")
        conn.commit()
        conn.close()

    def test_e2e_01_root_and_dashboards(self):
        # 1. Root route
        r_root = self.client.get("/")
        self.assertEqual(r_root.status_code, 200)

        # 2. Public Door Dashboard
        r_door = self.client.get("/door")
        self.assertEqual(r_door.status_code, 200)
        self.assertIn(b"Adaptive PQC Smart Door", r_door.data)

        # 3. Owner Dashboard
        r_owner = self.client.get("/owner")
        self.assertEqual(r_owner.status_code, 200)
        self.assertIn(b"Owner Security", r_owner.data)

    def test_e2e_02_health_probe(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["status"], "ok")

    def test_e2e_03_public_door_auth_success(self):
        r = self.client.post(
            "/api/authenticate",
            data=json.dumps({"password": "1234"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["door_state"], "OPEN")
        self.assertEqual(data["user"], "DAD")
        self.assertEqual(data["risk_level"], "LOW")
        self.assertIn("ML-KEM-512", data["security_profile"]["kem"])

    def test_e2e_04_public_door_auth_failure(self):
        r = self.client.post(
            "/api/authenticate",
            data=json.dumps({"password": "9999"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["authenticated"])
        self.assertEqual(data["door_state"], "LOCKED")
        self.assertEqual(data["user"], "UNKNOWN")

    def test_e2e_05_door_status_endpoint(self):
        r = self.client.get("/api/door/status")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("door_state", data)
        self.assertIn("risk_level", data)
        self.assertIn("pqc_profile", data)

    def test_e2e_06_owner_login_and_protected_analytics(self):
        # 1. Accessing analytics without auth must return 401
        r_unauth = self.client.get("/api/owner/analytics")
        self.assertEqual(r_unauth.status_code, 401)

        # 2. Login as admin
        r_login = self.client.post(
            "/api/owner/login",
            data=json.dumps({"username": "admin", "password": "test-owner-password"}),
            content_type="application/json",
        )
        self.assertEqual(r_login.status_code, 200)
        login_data = r_login.get_json()
        self.assertTrue(login_data["success"])
        token = login_data["token"]

        # 3. Access analytics with token in header or cookie
        r_auth = self.client.get(
            "/api/owner/analytics",
            headers={"X-Owner-Token": token},
        )
        self.assertEqual(r_auth.status_code, 200)
        data = r_auth.get_json()
        self.assertIn("total_attempts", data)
        self.assertIn("risk_distribution", data)

    def test_e2e_07_full_password_reset_flow(self):
        # Step 1: Request reset
        r_req = self.client.post(
            "/api/reset/request",
            data=json.dumps({"source": "WEB_TEST"}),
            content_type="application/json",
        )
        self.assertEqual(r_req.status_code, 200)

        # Step 2: Generate OTP
        r_otp = self.client.post("/api/reset/generate-otp")
        self.assertEqual(r_otp.status_code, 200)
        otp = r_otp.get_json()["otp"]
        self.assertEqual(len(otp), 6)

        # Step 3: Verify OTP
        r_ver = self.client.post(
            "/api/reset/verify-otp",
            data=json.dumps({"otp": otp}),
            content_type="application/json",
        )
        self.assertEqual(r_ver.status_code, 200)
        self.assertTrue(r_ver.get_json()["success"])

        # Step 4: Set new password 3456
        r_set = self.client.post(
            "/api/reset/set-password",
            data=json.dumps({"new_password": "3456", "confirm_password": "3456"}),
            content_type="application/json",
        )
        self.assertEqual(r_set.status_code, 200)
        self.assertTrue(r_set.get_json()["success"])

        # Step 5: Verify new password works on /api/authenticate
        r_auth_new = self.client.post(
            "/api/authenticate",
            data=json.dumps({"password": "3456"}),
            content_type="application/json",
        )
        self.assertTrue(r_auth_new.get_json()["authenticated"])

        # Step 6: Verify old password fails
        r_auth_old = self.client.post(
            "/api/authenticate",
            data=json.dumps({"password": "1234"}),
            content_type="application/json",
        )
        self.assertFalse(r_auth_old.get_json()["authenticated"])

    def test_e2e_08_device_authentication_and_telemetry(self):
        import hashlib
        pin_hash = hashlib.sha256("1234".encode()).hexdigest()

        # Restore PIN to 1234
        update_door_pin("1234", user_alias="DAD")

        r = self.client.post(
            "/api/device/authenticate",
            data=json.dumps({
                "device_id": "DOOR-001",
                "pin_hash": pin_hash,
                "ip_address": "192.168.1.150",
                "rssi": -55,
            }),
            content_type="application/json",
            headers={"X-Device-Token": "test-device-token-not-a-secret"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["user"], "DAD")

        # Check telemetry updated
        r_stat = self.client.get("/api/device/status?device_id=DOOR-001")
        self.assertEqual(r_stat.status_code, 200)
        stat_data = r_stat.get_json()
        self.assertEqual(stat_data["ip_address"], "192.168.1.150")
        self.assertEqual(stat_data["rssi"], -55)


if __name__ == "__main__":
    unittest.main()
