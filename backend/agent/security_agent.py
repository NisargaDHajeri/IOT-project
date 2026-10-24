
"""LangGraph Autonomous Security Agent for Adaptive PQC Smart Door Lock.

Eight-node workflow:
OBSERVE -> ASSESS -> REASSESS -> PLAN -> DECIDE -> ACT -> RECOMMEND -> REFLECT

Device model:
    Eight device telemetry features -> LOW / MEDIUM / HIGH

Network model:
    Thirty-nine CICIoT2023 features -> network attack class

Agent:
    Combines both model outputs, applies security rules, chooses a PQC
    profile and produces a security decision.
"""

from numbers import Real
from typing import Any, Dict, List, TypedDict

import numpy as np
from langgraph.graph import StateGraph, START, END
from config import FEATURES
from services.ml_classifier import predict_risk
from services.pqc_service import get_pqc_profile
from services.ciciot_classifier import (
    network_risk_from_prediction,
    predict_network_threat,
)


RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


class SecurityAgentState(TypedDict, total=False):
    context: Dict[str, Any]
    ml_risk_level: str
    ml_risk_confidence: Dict[str, float]
    device_risk_level: str
    network_prediction: Dict[str, Any]
    network_risk_level: str
    risk_level: str
    combined_risk_reason: str
    escalation_applied: bool
    escalation_reason: str
    observations: List[str]
    reasoning: List[str]
    plan: List[str]
    security_profile: Dict[str, Any]
    decision: Dict[str, Any]
    autonomous_action: Dict[str, Any]
    security_recommendations: List[str]
    reflection: Dict[str, Any]


def observe_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Observe device telemetry and any supplied network evidence."""
    context = state.get("context", {})
    observations = []

    failed_attempts = int(context.get("failed_auth_attempts", 0))
    velocity = float(context.get("attempt_velocity", 0.0))

    if failed_attempts >= 5:
        observations.append(
            f"Critical threshold: {failed_attempts} failed attempts."
        )
    elif failed_attempts >= 3:
        observations.append(
            f"Elevated failure count: {failed_attempts} failed attempts."
        )
    elif failed_attempts > 0:
        observations.append("An authentication failure was recorded.")
    else:
        observations.append("No failed authentication attempts reported.")

    if velocity >= 3.0:
        observations.append(
            f"High authentication attempt velocity: {velocity}/30 seconds."
        )

    if context.get("network_anomaly", 0) == 1:
        observations.append("Device telemetry reports a network anomaly.")

    if context.get("threat_indicator", 0) == 1:
        observations.append("Device threat indicator is active.")

    latency = float(context.get("communication_latency_ms", 0))
    if latency >= 200:
        observations.append(f"High device communication latency: {latency} ms.")

    if context.get("network_features") is not None:
        observations.append(
            "CICIoT2023 network-flow features were supplied for classification."
        )
    else:
        observations.append(
            "No CICIoT2023 feature vector supplied; network model will be skipped."
        )

    return {"observations": observations}


def assess_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Run both models when their respective inputs are available."""
    context = state.get("context", {})
    if not isinstance(context, dict):
        raise ValueError("Security context must be an object.")
    for feature in FEATURES:
        if feature not in context:
            continue
        value = context[feature]
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"Device feature '{feature}' must be numeric.")
        if not np.isfinite(float(value)):
            raise ValueError(f"Device feature '{feature}' must be finite.")

    # Model 1: existing device telemetry classifier.
    device_result = predict_risk(context)
    device_prediction = str(device_result["predicted_risk"]).upper()
    device_confidence = device_result.get("confidence", {})

    if device_prediction not in RISK_RANK:
        raise ValueError(
            f"Unexpected device risk class: {device_prediction}"
        )

    reasoning = [
        "Device Random Forest predicted "
        f"{device_prediction}; confidence "
        f"{device_confidence.get(device_result['predicted_risk'], 0.0):.2%}."
    ]

    # Default values explicitly indicate that network analysis was not run.
    network_result = {}
    network_risk = "UNKNOWN"

    # Model 2: CICIoT2023 network attack classifier.
    # It requires all 39 RAW features; the service applies the saved scaler.
    network_features = context.get("network_features")

    if network_features is not None:
        network_result = predict_network_threat(network_features)
        attack = str(network_result["predicted_attack"])
        confidence = float(network_result["max_confidence"])

        network_risk = network_risk_from_prediction(network_result)

        reasoning.append(
            f"CICIoT2023 Random Forest predicted {attack} "
            f"with {confidence:.2%} maximum class confidence; "
            f"mapped network risk to {network_risk}."
        )
    else:
        reasoning.append(
            "Network model skipped because network_features were not provided."
        )

    # Conservative fusion: the highest risk from the available models wins.
    risks = [device_prediction]
    if network_risk in RISK_RANK:
        risks.append(network_risk)

    combined_risk = max(risks, key=lambda risk: RISK_RANK[risk])

    combination_reason = (
        f"Device risk={device_prediction}; network risk={network_risk}; "
        f"combined risk={combined_risk}."
    )
    reasoning.append(combination_reason)

    return {
        # Keep the original field for compatibility with existing code.
        "ml_risk_level": device_prediction,
        "device_risk_level": device_prediction,
        "ml_risk_confidence": device_confidence,
        "network_prediction": network_result,
        "network_risk_level": network_risk,
        "risk_level": combined_risk,
        "combined_risk_reason": combination_reason,
        "reasoning": reasoning,
    }


def reassess_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Preserve combined risk and apply additional device security rules."""
    context = state.get("context", {})
    device_risk = state.get("ml_risk_level", "LOW")
    network_risk = state.get("network_risk_level", "UNKNOWN")
    reasoning = list(state.get("reasoning", []))

    risks = [device_risk]
    if network_risk in RISK_RANK:
        risks.append(network_risk)

    # Do not reset a network-driven HIGH risk to the device model's risk.
    final_risk = max(risks, key=lambda risk: RISK_RANK[risk])

    failed_attempts = int(context.get("failed_auth_attempts", 0))
    velocity = float(context.get("attempt_velocity", 0.0))

    if failed_attempts >= 5 or velocity >= 4.0:
        if final_risk != "HIGH":
            reasoning.append(
                "Escalated to HIGH because of repeated authentication "
                "failures or high attempt velocity."
            )
        final_risk = "HIGH"
    elif failed_attempts >= 3 and RISK_RANK[final_risk] < RISK_RANK["MEDIUM"]:
        final_risk = "MEDIUM"
        reasoning.append(
            "Escalated to MEDIUM because of repeated authentication failures."
        )

    escalated = RISK_RANK[final_risk] > RISK_RANK[device_risk]

    reason = (
        f"Combined assessment: device={device_risk}, "
        f"network={network_risk}, final={final_risk}."
        if escalated
        else ""
    )

    combination_reason = (
        f"Device risk={device_risk}; network risk={network_risk}; "
        f"final risk after security rules={final_risk}."
    )

    return {
        "risk_level": final_risk,
        "escalation_applied": escalated,
        "escalation_reason": reason,
        "combined_risk_reason": combination_reason,
        "reasoning": reasoning,
    }


def plan_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Plan a response based on the final combined risk."""
    risk = state.get("risk_level", "LOW")

    if risk == "HIGH":
        plan = [
            "Apply the configured high-risk authentication lockout policy.",
            "Select ML-KEM-1024 and ML-DSA-87 as the configured PQC profile.",
            "Raise a security alert and record the assessment.",
        ]
    elif risk == "MEDIUM":
        plan = [
            "Maintain the secure door state and increase monitoring.",
            "Select ML-KEM-768 and ML-DSA-65 as the configured PQC profile.",
            "Record a security warning.",
        ]
    else:
        plan = [
            "Use ML-KEM-512 and ML-DSA-44 as the configured PQC profile.",
            "Continue credential-based authorization checks.",
        ]

    return {"plan": plan}


def decide_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Choose an authorization decision from the final combined risk."""
    risk = state.get("risk_level", "LOW")
    context = state.get("context", {})
    is_authenticated = bool(context.get("is_authenticated", False))

    if risk == "HIGH":
        action = "LOCK_AUTHENTICATION"
        decision_code = "LOCKOUT"
        message = (
            "High combined security risk detected; authentication should "
            "be locked according to the configured policy."
        )
    elif risk == "MEDIUM":
        action = "INCREASE_MONITORING"
        decision_code = "DENY_MONITOR" if not is_authenticated else "MONITOR"
        message = (
            "Medium combined security risk; maintain protection and "
            "increase monitoring."
        )
    elif not is_authenticated:
        action = "RECORD_FAILED_ATTEMPT"
        decision_code = "DENY"
        message = "Credentials not authenticated; access is denied."
    else:
        action = "UNLOCK_DOOR"
        decision_code = "ALLOW"
        message = "Authentication succeeded and combined risk is LOW."

    return {
        "decision": {
            "decision": decision_code,
            "risk_level": risk,
            "message": message,
        },
        "autonomous_action": {
            "action": action,
            "message": message,
            "execution_status": "READY_FOR_EXECUTION",
        },
    }


def act_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Select the configured PQC profile for the final risk."""
    risk = state.get("risk_level", "LOW")
    profile = get_pqc_profile(risk)
    return {"security_profile": profile}


def recommend_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Generate recommendations based on the combined assessment."""
    risk = state.get("risk_level", "LOW")
    network = state.get("network_prediction", {})
    recommendations = []

    if risk == "HIGH":
        recommendations.extend([
            "Review the security audit for possible intrusion.",
            "Verify the integrity of the ESP8266 keypad and device.",
            "Keep access denied until the configured security policy permits recovery.",
        ])
    elif risk == "MEDIUM":
        recommendations.append(
            "Monitor device and network telemetry for repeated suspicious activity."
        )
    else:
        recommendations.append(
            "Continue normal monitoring and credential-based authorization."
        )

    if network:
        recommendations.append(
            "Review the CICIoT2023 network prediction and its confidence "
            "alongside the device model result."
        )

    return {"security_recommendations": recommendations}


def reflect_node(state: SecurityAgentState) -> Dict[str, Any]:
    """Summarize the evidence and decisions made during this agent cycle."""
    device_risk = state.get("ml_risk_level", "LOW")
    network_risk = state.get("network_risk_level", "UNKNOWN")
    final_risk = state.get("risk_level", "LOW")
    device_confidence = state.get("ml_risk_confidence", {})
    network_prediction = state.get("network_prediction", {})

    return {
        "reflection": {
            "evaluation_success": True,
            "device_model_risk": device_risk,
            "network_model_risk": network_risk,
            "network_attack": network_prediction.get(
                "predicted_attack", "NOT_PROVIDED"
            ),
            "agent_final": final_risk,
            "device_model_agreement": device_risk == final_risk,
            "confidence_score": device_confidence.get(device_risk, 0.0),
            "nodes_traversed": 8,
            "combined_risk_reason": state.get("combined_risk_reason", ""),
            "network_model_executed": bool(network_prediction),
        }
    }


def build_security_graph():
    """Construct and compile the eight-node LangGraph workflow."""
    graph = StateGraph(SecurityAgentState)

    graph.add_node("observe", observe_node)
    graph.add_node("assess", assess_node)
    graph.add_node("reassess", reassess_node)
    graph.add_node("plan", plan_node)
    graph.add_node("decide", decide_node)
    graph.add_node("act", act_node)
    graph.add_node("recommend", recommend_node)
    graph.add_node("reflect", reflect_node)

    graph.add_edge(START, "observe")
    graph.add_edge("observe", "assess")
    graph.add_edge("assess", "reassess")
    graph.add_edge("reassess", "plan")
    graph.add_edge("plan", "decide")
    graph.add_edge("decide", "act")
    graph.add_edge("act", "recommend")
    graph.add_edge("recommend", "reflect")
    graph.add_edge("reflect", END)

    return graph.compile()


_COMPILED_AGENT = build_security_graph()


def run_agent_pipeline(context: Dict[str, Any]) -> Dict[str, Any]:
    """Run the full agent pipeline for device and optional network evidence."""
    if not isinstance(context, dict):
        raise ValueError("Security context must be an object.")
    initial_state = {
        "context": context,
        "reasoning": [],
        "observations": [],
        "plan": [],
        "security_recommendations": [],
    }

    final_state = _COMPILED_AGENT.invoke(initial_state)
    final_state["agent_cycle"] = "COMPLETED"
    return final_state
