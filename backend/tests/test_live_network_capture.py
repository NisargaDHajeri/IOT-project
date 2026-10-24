"""Safe tests for passive network metadata capture and prototype persistence."""

import json
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import database
from services import live_network_capture as capture
from services.agent_service import (
    coordinate_security_evidence,
    record_live_network_prototype_assessment,
)
from services.ciciot_classifier import NETWORK_FEATURE_COLUMNS
from services.pqc_service import get_pqc_profile


class FakeLayer:
    def __init__(self, **values):
        self.__dict__.update(values)


class FakePacket:
    def __init__(self, layers):
        self.layers = layers
        self.time = 100.0
        self.queried_layers = []

    def haslayer(self, layer_type):
        self.queried_layers.append(layer_type.__name__)
        return layer_type in self.layers

    def getlayer(self, layer_type):
        self.queried_layers.append(layer_type.__name__)
        return self.layers.get(layer_type)


class FakeSniffer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.exception = None

    def start(self):
        self.running = True

    def stop(self, join=True):
        self.running = False


class TestLiveNetworkCapture(unittest.TestCase):
    @staticmethod
    def _evidence(risk, detector, timestamp=None):
        return {
            "status": "FRESH",
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "risk": risk,
            "model_prediction": f"{detector}_{risk}",
            "confidence": {risk: 0.99},
            "evidence": {"detector": detector},
        }

    def test_coordinator_risk_matrix_preserves_original_predictions(self):
        for device_risk in ("LOW", "MEDIUM", "HIGH"):
            for network_risk in ("LOW", "MEDIUM", "HIGH"):
                with self.subTest(device=device_risk, network=network_risk):
                    decision = coordinate_security_evidence(
                        self._evidence(device_risk, "device"),
                        self._evidence(network_risk, "network"),
                    )
                    expected = max(
                        (device_risk, network_risk),
                        key={"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get,
                    )
                    self.assertEqual(decision["final_risk"], expected)
                    self.assertEqual(
                        decision["detectors"]["device"]["model_prediction"],
                        f"device_{device_risk}",
                    )
                    self.assertEqual(
                        decision["detectors"]["network"]["model_prediction"],
                        f"network_{network_risk}",
                    )
                    self.assertIn("ASSESSMENT_ONLY", decision["policy_version"])

    def test_coordinator_missing_invalid_stale_and_conflicting_evidence(self):
        now = datetime.now(timezone.utc)
        stale = self._evidence(
            "LOW",
            "device",
            (now - timedelta(seconds=301)).isoformat(),
        )
        decision = coordinate_security_evidence(
            stale,
            self._evidence("LOW", "network", now.isoformat()),
            now=now,
        )
        self.assertEqual(decision["detectors"]["device"]["status"], "STALE")
        self.assertEqual(decision["final_risk"], "MEDIUM")
        self.assertTrue(any("not treated as LOW" in reason for reason in decision["reasoning"]))

        missing = coordinate_security_evidence(None, None, now=now)
        self.assertEqual(missing["detectors"]["device"]["status"], "MISSING")
        self.assertEqual(missing["detectors"]["network"]["status"], "MISSING")
        self.assertEqual(missing["final_risk"], "MEDIUM")

        invalid = self._evidence("HIGH", "network", now.isoformat())
        invalid["status"] = "INVALID"
        decision = coordinate_security_evidence(
            self._evidence("LOW", "device", now.isoformat()),
            invalid,
            now=now,
        )
        self.assertEqual(decision["final_risk"], "MEDIUM")
        self.assertEqual(decision["detectors"]["network"]["status"], "INVALID")

        conflict = coordinate_security_evidence(
            self._evidence("LOW", "device", now.isoformat()),
            self._evidence("HIGH", "network", now.isoformat()),
            now=now,
        )
        self.assertEqual(conflict["final_risk"], "HIGH")
        self.assertTrue(any("Conflicting" in reason for reason in conflict["reasoning"]))

    def test_coordinated_risks_select_existing_profiles_without_claiming_execution(self):
        expected_profiles = {
            "LOW": ("ML-KEM-512", "ML-DSA-44"),
            "MEDIUM": ("ML-KEM-768", "ML-DSA-65"),
            "HIGH": ("ML-KEM-1024", "ML-DSA-87"),
        }
        for risk, algorithms in expected_profiles.items():
            profile = get_pqc_profile(risk)
            self.assertEqual((profile["kem"], profile["signature"]), algorithms)
            self.assertIn(
                profile["execution_mode"],
                {"NATIVE_LIBOQS", "PROFILE_SELECTION_ONLY"},
            )

    def test_capture_routes_require_owner_and_do_not_start_on_dashboard_get(self):
        from flask import Flask
        import routes.owner_routes as owner_routes

        class FakeCapture:
            def __init__(self):
                self.started = False

            def snapshot(self, include_interfaces=False):
                return {
                    "status": "STOPPED",
                    "interfaces": (
                        [{"name": "authorized-test-interface", "description": "Test"}]
                        if include_interfaces else []
                    ),
                    "packet_count": 0,
                    "flow_count": 0,
                    "assessment_count": 0,
                    "assessment_mode": "ASSESSMENT_ONLY",
                    "feature_model_compatible": False,
                }

            def start(self, interface, duration_seconds):
                self.started = True
                self.interface = interface
                self.duration_seconds = duration_seconds
                return {**self.snapshot(), "status": "STARTING"}

            def stop(self):
                self.started = False
                return self.snapshot()

        fake_capture = FakeCapture()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(database, "DATABASE_PATH", Path(directory) / "owner-test.db"):
                database.init_db()
                test_app = Flask(__name__)
                test_app.register_blueprint(owner_routes.owner_bp)
                client = test_app.test_client()
                self.assertEqual(
                    client.get("/api/owner/network-capture").status_code,
                    401,
                )
                login = client.post(
                    "/api/owner/login",
                    json={"username": "admin", "password": "test-owner-password"},
                )
                self.assertEqual(login.status_code, 200)
                with patch.object(owner_routes, "live_network_capture", fake_capture):
                    status = client.get("/api/owner/network-capture")
                    self.assertEqual(status.status_code, 200)
                    self.assertFalse(fake_capture.started)
                    start = client.post(
                        "/api/owner/network-capture/start",
                        json={
                            "interface": "authorized-test-interface",
                            "duration_seconds": 60,
                        },
                    )
                    self.assertEqual(start.status_code, 202)
                    self.assertTrue(fake_capture.started)
                    stop = client.post("/api/owner/network-capture/stop")
                    self.assertEqual(stop.status_code, 200)
                    self.assertFalse(fake_capture.started)

    def test_windows_capture_reports_missing_npcap_without_starting(self):
        from scapy.config import conf

        if conf.use_pcap:
            self.skipTest("Npcap/libpcap provider is available in this environment.")
        with patch.object(capture.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(
                capture.CaptureUnavailable,
                "Npcap is required for Windows packet capture",
            ):
                capture.list_capture_interfaces()

    def test_header_metadata_builds_ordered_unvalidated_schema_prototype(self):
        layer_types = {
            name: type(name, (), {})
            for name in ("IP", "IPv6", "ARP", "TCP", "UDP", "ICMP", "IGMP", "LLC", "Ether")
        }
        packet = FakePacket({
            layer_types["Ether"]: FakeLayer(),
            layer_types["IP"]: FakeLayer(
                proto=6, ttl=64, ihl=5, len=60, src="192.0.2.10", dst="192.0.2.1"
            ),
            layer_types["TCP"]: FakeLayer(
                sport=12345, dport=443, dataofs=5, flags=0x12
            ),
        })
        with patch.object(
            capture, "_scapy_capture_api",
            return_value=(None, None, layer_types),
        ):
            metadata = capture.extract_packet_metadata(packet)

        self.assertEqual(metadata.packet_size, 74)
        self.assertEqual(metadata.protocol, "TCP")
        self.assertEqual(metadata.ttl, 64)
        self.assertEqual(metadata.tcp_flags, 0)
        self.assertEqual(metadata.service_ports, ())
        self.assertEqual(set(packet.queried_layers), {"IP", "Ether"})

        window = capture.NetworkWindow()
        for index in range(capture.MIN_PACKETS_PER_WINDOW):
            window.add(capture.PacketMetadata(
                timestamp=100 + index * 0.1,
                flow_key=("192.0.2.10", "192.0.2.1", "TCP", 12345, 443),
                packet_size=74,
                header_length=54,
                protocol_type=6,
                ttl=64,
                protocol="TCP",
                tcp_flags=0x12,
                service_ports=(12345, 443),
                is_ipv4=True,
            ))
        features = window.to_feature_vector(1.0)
        self.assertEqual(tuple(features), NETWORK_FEATURE_COLUMNS)
        self.assertEqual(len(features), 39)
        self.assertTrue(all(value >= 0 for value in features.values()))
        self.assertEqual(features["Number"], capture.MIN_PACKETS_PER_WINDOW)

    def test_capture_is_explicit_passive_bounded_and_stops_cleanly(self):
        manager = capture.LiveNetworkCapture(sniffer_factory=FakeSniffer)
        with patch.object(
            capture,
            "list_capture_interfaces",
            return_value=[{"name": "authorized-test-interface", "description": "Test"}],
        ):
            state = manager.start("authorized-test-interface", 10)
            self.assertIn(state["status"], {"STARTING", "RUNNING"})
            self.assertEqual(state["maximum_duration_seconds"], 300)
            self.assertTrue(manager._sniffer.kwargs["store"] is False)
            self.assertTrue(manager._sniffer.kwargs["promisc"] is False)
            self.assertEqual(manager._sniffer.kwargs["filter"], capture.CAPTURE_FILTER)
            self.assertEqual(capture.CAPTURE_SNAPLEN, 34)
            stopped = manager.stop()

        self.assertEqual(stopped["status"], "STOPPED")
        self.assertEqual(stopped["packet_count"], 0)
        with self.assertRaises(ValueError):
            manager.start("authorized-test-interface", 301)

    def test_live_prototype_persists_without_prediction_or_device_action(self):
        with tempfile.TemporaryDirectory() as directory:
            test_db = Path(directory) / "capture-test.db"
            with patch.object(database, "DATABASE_PATH", test_db):
                database.init_db()
                conn = database.get_db_connection()
                conn.execute(
                    """INSERT INTO agent_decisions (
                        decision_id, timestamp, ml_risk, final_risk,
                        escalation_applied, escalation_reason, action, message,
                        execution_status, pqc_kem, pqc_sig, reasoning_json,
                        observations_json, device_risk, network_risk,
                        network_prediction_json, device_confidence_json,
                        network_confidence_json, pqc_execution_mode
                    ) VALUES (?, ?, 'HIGH', 'HIGH', 0, '', 'RECORD', '',
                              'TEST_ONLY', 'ML-KEM-1024', 'ML-DSA-87', '[]',
                              '[]', 'HIGH', 'UNKNOWN', '{}', '{}', '{}',
                              'ASSESSMENT_ONLY')""",
                    (
                        "DEC-RECENT-DEVICE",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
                conn.close()
                features = {name: 0.0 for name in NETWORK_FEATURE_COLUMNS}
                with patch(
                    "services.ciciot_classifier.predict_network_threat",
                    side_effect=AssertionError(
                        "Unvalidated live proxies must not reach the model."
                    ),
                ):
                    result = record_live_network_prototype_assessment(
                        interface="authorized-test-interface",
                        capture_started_at="2026-01-01T00:00:00+00:00",
                        capture_ended_at="2026-01-01T00:00:10+00:00",
                        packet_count=10,
                        flow_count=1,
                        last_packet_at="2026-01-01T00:00:09+00:00",
                        features=features,
                    )
                duplicate = record_live_network_prototype_assessment(
                    interface="authorized-test-interface",
                    capture_started_at="2026-01-01T00:00:00+00:00",
                    capture_ended_at="2026-01-01T00:00:10+00:00",
                    packet_count=10,
                    flow_count=1,
                    last_packet_at="2026-01-01T00:00:09+00:00",
                    features=features,
                )
                conn = database.get_db_connection()
                decision = conn.execute(
                    """SELECT network_risk, final_risk, execution_status,
                              network_prediction_json, pqc_kem
                       FROM agent_decisions WHERE decision_id = ?""",
                    (result["decision_id"],),
                ).fetchone()
                command_count = conn.execute(
                    "SELECT COUNT(*) FROM commands"
                ).fetchone()[0]
                decision_count = conn.execute(
                    """SELECT COUNT(*) FROM agent_decisions
                       WHERE decision_id LIKE 'LIVE-%'"""
                ).fetchone()[0]
                conn.close()

        prediction = json.loads(decision["network_prediction_json"])
        self.assertEqual(decision["network_risk"], "UNVALIDATED")
        self.assertEqual(decision["final_risk"], "MEDIUM")
        self.assertEqual(decision["execution_status"], "ASSESSMENT_ONLY_NO_DOOR_ACTION")
        self.assertEqual(decision["pqc_kem"], "ML-KEM-768")
        self.assertFalse(prediction["model_compatible"])
        self.assertIsNone(prediction["max_confidence"])
        self.assertEqual(prediction["packet_count"], 10)
        self.assertEqual(
            prediction["network_evidence_status"],
            "LIVE NETWORK EVIDENCE",
        )
        self.assertEqual(
            prediction["model_inference_status"],
            "MODEL INFERENCE UNAVAILABLE",
        )
        self.assertIsNone(prediction["correlated_authentication_decision_id"])
        self.assertEqual(prediction["agent"]["detectors"]["device"]["status"], "MISSING")
        self.assertEqual(command_count, 0)
        self.assertTrue(duplicate["duplicate_event"])
        self.assertEqual(decision_count, 1)

    def test_concurrent_identical_windows_persist_once(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(
                database, "DATABASE_PATH", Path(directory) / "capture-concurrent.db"
            ):
                database.init_db()
                features = {name: 0.0 for name in NETWORK_FEATURE_COLUMNS}
                args = {
                    "interface": "authorized-test-interface",
                    "capture_started_at": "2026-01-01T00:00:00+00:00",
                    "capture_ended_at": "2026-01-01T00:00:10+00:00",
                    "packet_count": 10,
                    "flow_count": 1,
                    "last_packet_at": "2026-01-01T00:00:09+00:00",
                    "features": features,
                }
                with ThreadPoolExecutor(max_workers=4) as executor:
                    results = list(executor.map(
                        lambda _: record_live_network_prototype_assessment(**args),
                        range(8),
                    ))
                conn = database.get_db_connection()
                count = conn.execute(
                    """SELECT COUNT(*) FROM agent_decisions
                       WHERE decision_id LIKE 'LIVE-%'"""
                ).fetchone()[0]
                conn.close()

        self.assertEqual(count, 1)
        self.assertEqual(len({result["decision_id"] for result in results}), 1)
        self.assertEqual(sum(not result["duplicate_event"] for result in results), 1)

    def test_fake_live_window_persists_and_appears_in_owner_api(self):
        from flask import Flask
        import routes.owner_routes as owner_routes

        manager = capture.LiveNetworkCapture(sniffer_factory=FakeSniffer)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(database, "DATABASE_PATH", Path(directory) / "capture-api.db"):
                database.init_db()
                with patch.object(
                    capture,
                    "list_capture_interfaces",
                    return_value=[{
                        "name": "authorized-test-interface",
                        "description": "Test",
                    }],
                ):
                    manager.start("authorized-test-interface", 10)
                    packet_time = time.time()
                    with patch.object(
                        capture,
                        "extract_packet_metadata",
                        side_effect=lambda packet: packet,
                    ):
                        for index in range(capture.MIN_PACKETS_PER_WINDOW):
                            manager._on_packet(capture.PacketMetadata(
                                timestamp=packet_time + index * 0.01,
                                flow_key=("192.0.2.10", "192.0.2.1", "TCP"),
                                packet_size=74,
                                header_length=54,
                                protocol_type=6,
                                ttl=64,
                                protocol="TCP",
                                is_ipv4=True,
                            ))
                        stopped = manager.stop()

                test_app = Flask(__name__)
                test_app.register_blueprint(owner_routes.owner_bp)
                client = test_app.test_client()
                login = client.post(
                    "/api/owner/login",
                    json={"username": "admin", "password": "test-owner-password"},
                )
                self.assertEqual(login.status_code, 200)
                response = client.get("/api/owner/network-assessments?limit=10")
                self.assertEqual(response.status_code, 200)
                assessments = response.get_json()
                commands = database.get_db_connection().execute(
                    "SELECT COUNT(*) FROM commands"
                ).fetchone()[0]

        self.assertEqual(stopped["status"], "STOPPED")
        self.assertEqual(stopped["assessment_count"], 1)
        self.assertEqual(len(assessments), 1)
        assessment = assessments[0]
        self.assertEqual(assessment["assessment_source"], "LIVE_PACKET_CAPTURE_PROTOTYPE")
        self.assertEqual(assessment["network_prediction"]["packet_count"], 10)
        self.assertEqual(assessment["execution_status"], "ASSESSMENT_ONLY_NO_DOOR_ACTION")
        self.assertEqual(commands, 0)


if __name__ == "__main__":
    unittest.main()
