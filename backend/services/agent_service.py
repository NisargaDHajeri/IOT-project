"""Agent Service Interface for LangGraph Workflow Execution & Persistence."""

import json
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from database import get_db_connection
from agent.security_agent import run_agent_pipeline
from services.pqc_service import get_pqc_profile


class AgentPersistenceError(RuntimeError):
    """Raised when an agent decision cannot be durably recorded."""


COORDINATOR_POLICY_VERSION = "ASSESSMENT_ONLY_V1"
EVIDENCE_FRESHNESS_SECONDS = 300
COORDINATOR_RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def coordinate_security_evidence(
    device_evidence: Optional[Dict[str, Any]],
    network_evidence: Optional[Dict[str, Any]],
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Combine independent, fresh predictions; unknown evidence fails safe to MEDIUM."""
    current_time = now or datetime.now(timezone.utc)
    evidence_states = {}
    supported_risks = []
    reasons = []

    for detector, evidence in (
        ("device", device_evidence),
        ("network", network_evidence),
    ):
        if not evidence:
            evidence_states[detector] = {
                "status": "MISSING",
                "timestamp": None,
                "risk": None,
            }
            reasons.append(f"{detector.capitalize()} evidence is missing.")
            continue

        status = str(evidence.get("status", "INVALID")).upper()
        timestamp = evidence.get("timestamp")
        observed_at = None
        if timestamp:
            try:
                observed_at = datetime.fromisoformat(
                    str(timestamp).replace("Z", "+00:00")
                )
                if observed_at.tzinfo is None:
                    observed_at = observed_at.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                status = "INVALID"
        if status == "FRESH" and observed_at is not None:
            age = (current_time - observed_at.astimezone(timezone.utc)).total_seconds()
            if age < 0 or age > EVIDENCE_FRESHNESS_SECONDS:
                status = "STALE"

        risk = str(evidence.get("risk", "")).upper()
        if status == "FRESH" and risk in COORDINATOR_RISK_RANK:
            supported_risks.append((detector, risk))
            reasons.append(
                f"Fresh {detector} assessment supports {risk} risk."
            )
        else:
            risk = risk if risk in COORDINATOR_RISK_RANK else None
            reasons.append(
                f"{detector.capitalize()} evidence is {status.lower()}; "
                "it was not treated as LOW."
            )

        evidence_states[detector] = {
            "status": status,
            "timestamp": timestamp,
            "risk": risk,
            "model_prediction": evidence.get("model_prediction"),
            "confidence": evidence.get("confidence", {}),
            "evidence": evidence.get("evidence", {}),
        }

    if len(supported_risks) != 2:
        # Explicit fail-safe for partial or unvalidated independent evidence.
        risk = max(
            [risk for _, risk in supported_risks] + ["MEDIUM"],
            key=lambda level: COORDINATOR_RISK_RANK[level],
        )
        reasons.append(
            "Fail-safe policy: partial, missing, stale, or invalid detector "
            "evidence sets a minimum coordinated risk of MEDIUM."
        )
    else:
        risk = max(
            (risk for _, risk in supported_risks),
            key=lambda level: COORDINATOR_RISK_RANK[level],
        )

    if len(supported_risks) == 2 and supported_risks[0][1] == supported_risks[1][1]:
        reasons.append(
            f"Both independent detectors agree on {supported_risks[0][1]} risk."
        )
    elif len(supported_risks) == 2:
        reasons.append(
            "Conflicting fresh risk levels use the more severe explicit risk; "
            "model confidence values are not averaged."
        )

    return {
        "policy_version": COORDINATOR_POLICY_VERSION,
        "final_risk": risk,
        "detectors": evidence_states,
        "reasoning": reasons,
        "risk_reason": (
            f"Coordinated risk is {risk} using independent detector evidence "
            "and the explicit partial-evidence fail-safe policy."
        ),
        "evidence_freshness_seconds": EVIDENCE_FRESHNESS_SECONDS,
    }


def record_action_execution(decision_id: str, status: str) -> None:
    """Persist the outcome of an action selected by the security agent."""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE agent_decisions SET execution_status = ? WHERE decision_id = ?",
            (status, decision_id),
        )
        if cursor.rowcount != 1:
            raise AgentPersistenceError("Agent decision record was not found.")
        conn.commit()
    except Exception as exc:
        conn.rollback()
        if isinstance(exc, AgentPersistenceError):
            raise
        raise AgentPersistenceError(
            "Unable to persist the security action outcome."
        ) from exc
    finally:
        conn.close()


def analyze_security_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Executes the 8-node LangGraph workflow and saves the decision into SQLite.
    
    Returns the enriched agent result dictionary.
    """
    result = run_agent_pipeline(context)
    
    decision_id = f"DEC-{secrets.token_hex(4).upper()}"
    assessment_id = f"RSK-{secrets.token_hex(4).upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    
    ml_risk = result.get("ml_risk_level", "LOW")
    device_risk = result.get("device_risk_level", ml_risk)
    final_risk = result.get("risk_level", "LOW")
    conf = result.get("ml_risk_confidence", {})
    network_prediction = result.get("network_prediction") or {}
    network_confidence = network_prediction.get("confidence", {})
    sec_prof = result.get("security_profile", {})
    action = result.get("autonomous_action", {})
    
    # Save into SQLite database
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 1. Record Risk Assessment
        cursor.execute(
            """INSERT INTO risk_assessments (
                assessment_id, timestamp, battery_level, cpu_utilization, memory_usage,
                failed_auth_attempts, communication_latency_ms, network_anomaly, threat_indicator,
                ml_predicted_risk, ml_confidence_json, model_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                assessment_id,
                now_iso,
                context.get("battery_level", 80),
                context.get("cpu_utilization", 20),
                context.get("memory_usage", 30),
                context.get("failed_auth_attempts", 0),
                context.get("communication_latency_ms", 40),
                context.get("network_anomaly", 0),
                context.get("threat_indicator", 0),
                ml_risk,
                json.dumps(conf),
                "RandomForest-v2.1",
            ),
        )

        # 2. Record Agent Decision
        cursor.execute(
            """INSERT INTO agent_decisions (
                decision_id, timestamp, ml_risk, final_risk, escalation_applied, escalation_reason,
                action, message, execution_status, pqc_kem, pqc_sig, reasoning_json, observations_json,
                device_risk, network_risk, network_prediction_json, device_confidence_json,
                network_confidence_json, pqc_execution_mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                decision_id,
                now_iso,
                ml_risk,
                final_risk,
                1 if result.get("escalation_applied") else 0,
                result.get("escalation_reason", ""),
                action.get("action", "RECORD_ATTEMPT"),
                action.get("message", ""),
                action.get("execution_status", "COMPLETED"),
                sec_prof.get("kem", "ML-KEM-512"),
                sec_prof.get("signature", "ML-DSA-44"),
                json.dumps(result.get("reasoning", [])),
                json.dumps(result.get("observations", [])),
                device_risk,
                result.get("network_risk_level", "UNKNOWN"),
                json.dumps(network_prediction),
                json.dumps(conf),
                json.dumps(network_confidence),
                sec_prof.get("execution_mode", "PROFILE_SELECTION_ONLY"),
            ),
        )

        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise AgentPersistenceError(
            "Unable to persist the security decision."
        ) from exc
    finally:
        conn.close()

    result["device_risk_level"] = device_risk
    result["network_confidence"] = network_confidence
    result["decision_id"] = decision_id
    result["assessment_id"] = assessment_id
    result["timestamp"] = now_iso
    return result


def record_live_network_prototype_assessment(
    interface: str,
    capture_started_at: str,
    capture_ended_at: str,
    packet_count: int,
    flow_count: int,
    last_packet_at: str,
    features: Dict[str, float],
) -> Dict[str, Any]:
    """Persist live metadata without treating CICIoT-shaped proxies as predictions."""
    from services.ciciot_classifier import NETWORK_FEATURE_COLUMNS

    if tuple(features) != NETWORK_FEATURE_COLUMNS:
        raise ValueError("Live prototype features do not match the network schema.")

    now_iso = datetime.now(timezone.utc).isoformat()
    device_evidence = None
    coordinated = coordinate_security_evidence(
        device_evidence,
        {
            "status": "INVALID",
            "timestamp": capture_ended_at,
            "risk": None,
            "model_prediction": None,
            "confidence": {},
            "evidence": {
                "reason": (
                    "Captured live metadata is not reliably correlated to an "
                    "authentication event, and its CICIoT2023 feature semantics "
                    "are not validated."
                ),
            },
        },
    )
    profile = get_pqc_profile(coordinated["final_risk"])
    correlation = "|".join((
        interface,
        capture_started_at,
        capture_ended_at,
    ))
    event_fingerprint = hashlib.sha256(correlation.encode("utf-8")).hexdigest()[:16].upper()
    decision_id = f"LIVE-{event_fingerprint}"
    assessment_id = f"RSK-LIVE-{event_fingerprint}"
    prediction = {
        "assessment_type": "LIVE_PACKET_CAPTURE_PROTOTYPE",
        "assessment_source": "LIVE",
        "live_capture": True,
        "model": "CICIoT2023-RandomForest",
        "prediction_status": "NOT_RUN_FEATURE_SEMANTICS_UNVALIDATED",
        "network_evidence_status": "LIVE NETWORK EVIDENCE",
        "model_inference_status": "MODEL INFERENCE UNAVAILABLE",
        "model_compatible": False,
        "feature_schema_count": len(NETWORK_FEATURE_COLUMNS),
        "feature_order_validated": True,
        "feature_semantics_validated": False,
        "predicted_attack": None,
        "max_confidence": None,
        "confidence": {},
        "interface": interface,
        "capture_started_at": capture_started_at,
        "capture_ended_at": capture_ended_at,
        "last_packet_at": last_packet_at,
        "packet_count": packet_count,
        "flow_count": flow_count,
        "correlation_id": decision_id,
        "correlated_authentication_decision_id": None,
        "device_evidence": coordinated["detectors"]["device"],
        "network_evidence": coordinated["detectors"]["network"],
        "agent": coordinated,
        "pqc_selection_reason": (
            f"{profile['name']} profile selected from coordinated "
            f"{coordinated['final_risk']} risk under {coordinated['policy_version']}."
        ),
        "recommended_action": (
            "Review captured network metadata and validate CICIoT-compatible "
            "feature extraction before enabling network ML inference."
        ),
        "action_acknowledgement": "NOT_APPLICABLE_ASSESSMENT_ONLY",
    }
    reasoning = coordinated["reasoning"] + [
        "Passive live packet metadata was summarized for the selected interface.",
        "CICIoT2023 live feature semantics are not validated; network model inference "
        "was deliberately skipped.",
        "Assessment-only mode: no door, device, lockout, or network action was run.",
    ]

    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """SELECT decision_id, timestamp, final_risk,
                      network_prediction_json, pqc_kem, pqc_sig, execution_status
               FROM agent_decisions WHERE decision_id = ?""",
            (decision_id,),
        ).fetchone()
        if existing is not None:
            conn.rollback()
            saved = dict(existing)
            saved["network_prediction"] = json.loads(
                saved.pop("network_prediction_json") or "{}"
            )
            saved["network_risk"] = "UNVALIDATED"
            saved["device_risk"] = (
                device_evidence["model_prediction"] if device_evidence else "UNAVAILABLE"
            )
            saved["coordinated_evidence"] = saved["network_prediction"]["agent"]
            saved["security_profile"] = profile
            saved["duplicate_event"] = True
            return saved
        conn.execute(
            """INSERT INTO risk_assessments (
                assessment_id, timestamp, battery_level, cpu_utilization, memory_usage,
                failed_auth_attempts, communication_latency_ms, network_anomaly,
                threat_indicator, ml_predicted_risk, ml_confidence_json, model_version
            ) VALUES (?, ?, NULL, NULL, NULL, ?, NULL, NULL, NULL, ?, ?, ?)""",
            (
                assessment_id,
                now_iso,
                None,
                "UNAVAILABLE",
                json.dumps({}),
                "LIVE-METADATA-PROTOTYPE",
            ),
        )
        conn.execute(
            """INSERT INTO agent_decisions (
                decision_id, timestamp, ml_risk, final_risk, escalation_applied,
                escalation_reason, action, message, execution_status, pqc_kem,
                pqc_sig, reasoning_json, observations_json, device_risk,
                network_risk, network_prediction_json, device_confidence_json,
                network_confidence_json, pqc_execution_mode
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                decision_id,
                now_iso,
                device_evidence["model_prediction"] if device_evidence else "UNAVAILABLE",
                coordinated["final_risk"],
                coordinated["risk_reason"],
                "ASSESS_ONLY",
                "Live metadata prototype; network model unvalidated; no device action.",
                "ASSESSMENT_ONLY_NO_DOOR_ACTION",
                profile["kem"],
                profile["signature"],
                json.dumps(reasoning),
                json.dumps([]),
                device_evidence["model_prediction"] if device_evidence else "UNKNOWN",
                "UNVALIDATED",
                json.dumps(prediction),
                json.dumps(
                    device_evidence["confidence"] if device_evidence else {}
                ),
                json.dumps({}),
                "ASSESSMENT_ONLY",
            ),
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise AgentPersistenceError(
            "Unable to persist the live network prototype assessment."
        ) from exc
    finally:
        conn.close()

    return {
        "decision_id": decision_id,
        "assessment_id": assessment_id,
        "duplicate_event": False,
        "timestamp": now_iso,
        "network_prediction": prediction,
        "network_risk": "UNVALIDATED",
        "device_risk": device_evidence["risk"] if device_evidence else "UNAVAILABLE",
        "final_risk": coordinated["final_risk"],
        "coordinated_evidence": coordinated,
        "security_profile": profile,
        "pqc_selection_reason": prediction["pqc_selection_reason"],
        "recommended_action": prediction["recommended_action"],
        "execution_status": "ASSESSMENT_ONLY_NO_DOOR_ACTION",
    }
