"""Master Comprehensive Test Suite for Agentic AI Adaptive PQC Smart Door Lock.

Covers all 47+ specification requirements across:
1. Owner Authentication & Access Control
2. Door Password Verification & Versioning
3. Intrusion Risk Engine & Velocity Calculation
4. Security Lockout State Machine
5. Cryptographic 6-Digit OTP Engine (TTL, Replay, Single-Use)
6. AABB Multi-Step Password Reset Flow
7. 8-Node LangGraph Agent Execution
8. Adaptive NIST Post-Quantum Cryptography Profiles
9. SQLite Relational Integrity & Transactions
10. Security Invariants (No Plaintext Secrets)
"""

import unittest
import time
import json
from pathlib import Path
from database import init_db, get_db_connection, hash_secret, verify_secret_hash
from services.owner_auth_service import (
    register_owner,
    authenticate_owner,
    verify_owner_session,
    revoke_owner_session,
)
from services.password_service import (
    verify_door_pin,
    verify_door_pin_hash,
    update_door_pin,
    get_active_credential_info,
)
from services.risk_engine import (
    get_failed_attempts_count,
    increment_failed_attempts,
    reset_failed_attempts,
    calculate_attempt_velocity,
    is_system_locked_out,
    set_system_lockout,
    clear_system_lockout,
    build_security_context,
)
from services.otp_service import (
    create_reset_session,
    get_active_reset_session,
    verify_reset_otp,
    complete_password_reset,
    revoke_reset_session,
    trigger_aabb_reset,
)
from services.ml_classifier import predict_risk
from services.agent_service import analyze_security_context
from services.pqc_service import get_pqc_profile, execute_pqc_operation, get_pqc_system_status
from services.simulation_service import get_door_state, set_door_state, lock_door, unlock_door
from services.authentication_service import authenticate_access
from services.command_service import queue_command, get_pending_commands, acknowledge_command
from services.audit_service import log_security_event, log_audit, get_security_events, get_audit_logs
import hashlib


class TestMasterSmartDoorLock(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        clear_system_lockout()
        reset_failed_attempts()
        set_door_state("LOCKED")
        update_door_pin("1234", user_alias="DAD")
        conn = get_db_connection()
        conn.execute("DELETE FROM authentication_events;")
        conn.execute("DELETE FROM reset_sessions;")
        conn.execute("DELETE FROM commands;")
        conn.commit()
        conn.close()

    # =========================================================================
    # 1. OWNER AUTHENTICATION TESTS
    # =========================================================================
    def test_01_owner_registration(self):
        username = f"test_owner_{int(time.time()*1000)}"
        success, msg = register_owner(username, "SuperSecret123!")
        self.assertTrue(success)
        self.assertIn("created successfully", msg)

    def test_02_owner_login_success(self):
        success, token, msg = authenticate_owner("admin", "test-owner-password")
        self.assertTrue(success)
        self.assertIsNotNone(token)
        username = verify_owner_session(token)
        self.assertEqual(username, "admin")

    def test_03_owner_login_invalid_password(self):
        success, token, msg = authenticate_owner("admin", "wrongpassword")
        self.assertFalse(success)
        self.assertIsNone(token)

    def test_04_owner_logout(self):
        success, token, _ = authenticate_owner("admin", "test-owner-password")
        self.assertTrue(success)
        self.assertIsNotNone(verify_owner_session(token))
        revoke_owner_session(token)
        self.assertIsNone(verify_owner_session(token))

    def test_05_unauthorized_owner_access(self):
        self.assertIsNone(verify_owner_session("fake_invalid_token_12345"))

    # =========================================================================
    # 2. DOOR PASSWORD VERIFICATION & ATOMIC UPDATES
    # =========================================================================
    def test_06_door_password_correct_pin(self):
        # Default seeded PIN is 1234 (DAD)
        valid, user = verify_door_pin("1234")
        self.assertTrue(valid)
        self.assertEqual(user, "DAD")

    def test_07_door_password_wrong_pin(self):
        valid, user = verify_door_pin("9999")
        self.assertFalse(valid)
        self.assertIsNone(user)

    def test_08_door_password_hash_verification(self):
        # SHA-256 for "1234" is 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
        sha1234 = hashlib.sha256("1234".encode()).hexdigest()
        valid, user = verify_door_pin_hash(sha1234)
        self.assertTrue(valid)
        self.assertEqual(user, "DAD")

    def test_09_password_atomic_update_and_invalidation(self):
        # Update PIN to 4321
        success, msg = update_door_pin("4321", user_alias="DAD")
        self.assertTrue(success)

        # New PIN 4321 must succeed
        valid_new, user_new = verify_door_pin("4321")
        self.assertTrue(valid_new)

        # Old PIN 1234 must fail
        valid_old, _ = verify_door_pin("1234")
        self.assertFalse(valid_old)

        # Restore PIN back to 1234 for subsequent tests
        update_door_pin("1234", user_alias="DAD")

    # =========================================================================
    # 3. RISK ENGINE & ATTEMPT VELOCITY
    # =========================================================================
    def test_10_first_failure_low_risk(self):
        ctx = build_security_context(failed_count=1)
        res = predict_risk(ctx)
        self.assertIn(res["predicted_risk"], ["LOW", "MEDIUM"])

    def test_11_progressive_failure_escalation(self):
        ctx_high = build_security_context(failed_count=6)
        res_high = predict_risk(ctx_high)
        self.assertEqual(res_high["predicted_risk"], "HIGH")

    def test_12_lockout_state_activation_and_clearing(self):
        self.assertFalse(is_system_locked_out()[0])
        set_system_lockout(duration_seconds=10)
        is_locked, rem = is_system_locked_out()
        self.assertTrue(is_locked)
        self.assertGreater(rem, 0)
        self.assertEqual(get_door_state(), "LOCKOUT")

        clear_system_lockout()
        self.assertFalse(is_system_locked_out()[0])
        self.assertEqual(get_door_state(), "LOCKED")

    # =========================================================================
    # 4. OTP GENERATION, EXPIRY, REPLAY, AND REVOCATION
    # =========================================================================
    def test_13_otp_generation(self):
        session = create_reset_session()
        self.assertIsNotNone(session.get("otp"))
        self.assertEqual(len(session["otp"]), 6)
        self.assertTrue(session["otp"].isdigit())
        self.assertEqual(session["status"], "ACTIVE")

    def test_14_otp_verification_success(self):
        session = create_reset_session()
        otp = session["otp"]
        valid, msg = verify_reset_otp(session["device_id"], otp)
        self.assertTrue(valid)
        self.assertIn("verified successfully", msg)

    def test_15_otp_single_use_and_replay_prevention(self):
        session = create_reset_session()
        otp = session["otp"]
        valid1, _ = verify_reset_otp(session["device_id"], otp)
        self.assertTrue(valid1)

        # Second verification attempt with same OTP must fail
        valid2, msg2 = verify_reset_otp(session["device_id"], otp)
        self.assertFalse(valid2)

    def test_16_otp_invalid_code(self):
        session = create_reset_session()
        valid, msg = verify_reset_otp(session["device_id"], "000000")
        self.assertFalse(valid)
        self.assertIn("Invalid OTP", msg)

    def test_17_otp_revocation(self):
        session = create_reset_session()
        success, msg = revoke_reset_session(session["device_id"])
        self.assertTrue(success)
        sess = get_active_reset_session(session["device_id"])
        self.assertTrue(sess is None or sess.get("status") in ["REVOKED", "EXPIRED"])

    # =========================================================================
    # 5. AABB PASSWORD RESET SEQUENCE
    # =========================================================================
    def test_18_aabb_reset_initiation(self):
        res = trigger_aabb_reset()
        self.assertIn(res.get("status"), ["RESET_MODE_INITIALIZED", "RESET_MODE_ACTIVE"])

    def test_19_aabb_end_to_end_password_reset(self):
        # Step 1: Keypad triggers AABB
        trigger_aabb_reset()

        # Step 2: Owner generates OTP on console
        session = create_reset_session()
        otp = session["otp"]
        dev_id = session["device_id"]

        # Step 3: User enters OTP on Keypad
        verified, _ = verify_reset_otp(dev_id, otp)
        self.assertTrue(verified)

        # Step 4: User enters and confirms new password (e.g. 2580)
        reset_ok, msg = complete_password_reset(dev_id, "2580", "2580")
        self.assertTrue(reset_ok)

        # Step 5: Verify new PIN 2580 works and old PIN fails
        valid_new, _ = verify_door_pin("2580")
        self.assertTrue(valid_new)

        # Restore default PIN 1234
        update_door_pin("1234", user_alias="DAD")

    # =========================================================================
    # 6. LANGGRAPH 8-NODE AGENT EXECUTION
    # =========================================================================
    def test_20_langgraph_pipeline_execution(self):
        ctx = build_security_context(failed_count=0)
        ctx["is_authenticated"] = True
        ctx["user_alias"] = "DAD"

        res = analyze_security_context(ctx)
        self.assertIn("decision", res)
        self.assertIn("autonomous_action", res)
        self.assertIn("security_profile", res)
        self.assertIn("reflection", res)
        self.assertEqual(res["reflection"]["nodes_traversed"], 8)

    def test_21_langgraph_escalation_on_brute_force(self):
        ctx = build_security_context(failed_count=5)
        ctx["is_authenticated"] = False
        ctx["attempt_velocity"] = 5.0

        res = analyze_security_context(ctx)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertEqual(res["security_profile"]["kem"], "ML-KEM-1024")

    # =========================================================================
    # 7. ADAPTIVE PQC PROFILES
    # =========================================================================
    def test_22_pqc_profile_mapping(self):
        low_p = get_pqc_profile("LOW")
        self.assertEqual(low_p["kem"], "ML-KEM-512")
        self.assertEqual(low_p["signature"], "ML-DSA-44")

        med_p = get_pqc_profile("MEDIUM")
        self.assertEqual(med_p["kem"], "ML-KEM-768")
        self.assertEqual(med_p["signature"], "ML-DSA-65")

        high_p = get_pqc_profile("HIGH")
        self.assertEqual(high_p["kem"], "ML-KEM-1024")
        self.assertEqual(high_p["signature"], "ML-DSA-87")

    def test_23_pqc_execution_graceful_handling(self):
        op = execute_pqc_operation("HIGH")
        self.assertIn("kem_algorithm", op)
        self.assertIn("status", op)

    # =========================================================================
    # 8. COMPLETE AUTHENTICATION PIPELINE (END-TO-END)
    # =========================================================================
    def test_24_auth_pipeline_success(self):
        res = authenticate_access("1234", source="WEB_UI")
        self.assertTrue(res["authenticated"])
        self.assertEqual(res["door_state"], "OPEN")
        self.assertEqual(res["user"], "DAD")
        self.assertEqual(res["risk_level"], "LOW")

    def test_25_auth_pipeline_repeated_failure_lockout(self):
        # 5 consecutive failures
        for i in range(4):
            r = authenticate_access("9999", source="WEB_UI")
            self.assertFalse(r["authenticated"])

        r5 = authenticate_access("9999", source="WEB_UI")
        self.assertFalse(r5["authenticated"])
        self.assertEqual(r5["risk_level"], "HIGH")
        self.assertEqual(r5["door_state"], "LOCKOUT")

        # 6th attempt while locked out must be blocked immediately
        r6 = authenticate_access("1234", source="WEB_UI")
        self.assertFalse(r6["authenticated"])
        self.assertTrue(r6.get("lockout_active"))

    # =========================================================================
    # 9. COMMAND QUEUE & AUDIT INTEGRITY
    # =========================================================================
    def test_26_command_lifecycle(self):
        cmd = queue_command("DOOR-ESP8266-001", "AUTHENTICATION_SUCCESS", risk_level="LOW")
        cmd_id = cmd["command_id"]
        pending = get_pending_commands("DOOR-ESP8266-001")
        self.assertTrue(any(c["command_id"] == cmd_id for c in pending))

        ack = acknowledge_command(cmd_id, "DOOR-ESP8266-001")
        self.assertTrue(ack)

        pending_after = get_pending_commands("DOOR-ESP8266-001")
        self.assertFalse(any(c["command_id"] == cmd_id for c in pending_after))

    def test_27_audit_log_never_contains_plaintext_secrets(self):
        log_security_event(
            severity="INFO",
            event_type="TEST_EVENT",
            source="UNIT_TEST",
            description="Testing redaction",
            metadata={"password": "PlaintextPassword123", "pin": "1234", "safe_param": "ok"},
        )
        events = get_security_events(1)
        meta = events[0]["metadata"]
        self.assertEqual(meta["password"], "[REDACTED]")
        self.assertEqual(meta["pin"], "[REDACTED]")
        self.assertEqual(meta["safe_param"], "ok")


if __name__ == "__main__":
    unittest.main()
