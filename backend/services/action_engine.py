def choose_action(risk, context):
    if risk == "HIGH":
        return {
            "action": "LOCK_AUTHENTICATION",
            "message": "Authentication locked because the agent classified the environment as HIGH risk.",
        }

    if risk == "MEDIUM":
        return {
            "action": "INCREASE_MONITORING",
            "message": "Increase monitoring, logging, and authentication protection.",
        }

    return {
        "action": "NORMAL_OPERATION",
        "message": "Continue normal secure door-lock operation.",
    }


def door_action(risk_level, authenticated=False):
    if authenticated:
        return {
            "action": "OPEN_DOOR",
            "message": "Authorized authentication accepted. Door opened.",
        }

    if risk_level == "HIGH":
        return {
            "action": "LOCK_AUTHENTICATION",
            "message": "Authentication temporarily locked.",
        }

    if risk_level == "MEDIUM":
        return {
            "action": "INCREASE_MONITORING",
            "message": "Increase monitoring and security logging.",
        }

    return {
        "action": "RECORD_FAILED_ATTEMPT",
        "message": "Failed authentication recorded.",
    }
