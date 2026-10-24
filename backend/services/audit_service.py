"""Audit Logging & Security Event Service."""

import json
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from database import get_db_connection


def log_security_event(
    severity: str,
    event_type: str,
    source: str,
    description: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Logs an immutable security event into SQLite. Never logs plaintext credentials."""
    event_id = f"SEC-{secrets.token_hex(4).upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    
    clean_meta = dict(metadata or {})
    # Strip any potential sensitive keys
    for sensitive_key in ["password", "pin", "otp", "secret", "token", "password_hash"]:
        if sensitive_key in clean_meta:
            clean_meta[sensitive_key] = "[REDACTED]"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO security_events (event_id, timestamp, severity, event_type, source, description, metadata_json)
           VALUES (?, ?, ?, ?, ?, ?, ?);""",
        (event_id, now_iso, severity.upper(), event_type.upper(), source, description, json.dumps(clean_meta)),
    )
    conn.commit()
    conn.close()
    return event_id


def log_audit(
    actor: str,
    action: str,
    source: str,
    details: str,
    status: str = "OK",
):
    """Logs system administrative and operational actions."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO audit_logs (timestamp, actor, action, source, details, status)
           VALUES (?, ?, ?, ?, ?, ?);""",
        (now_iso, actor, action, source, details, status),
    )
    conn.commit()
    conn.close()


def get_security_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent security events."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT event_id, timestamp, severity, event_type, source, description, metadata_json
           FROM security_events ORDER BY id DESC LIMIT ?;""",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()

    events = []
    for r in rows:
        item = dict(r)
        try:
            item["metadata"] = json.loads(item.get("metadata_json") or "{}")
        except Exception:
            item["metadata"] = {}
        events.append(item)
    return events


def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent audit logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, timestamp, actor, action, source, details, status FROM audit_logs ORDER BY id DESC LIMIT ?;",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
