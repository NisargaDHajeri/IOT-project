"""Owner Authentication & Session Management Service.

Guarantees:
- Strict separation between public door users and owner console
- PBKDF2-HMAC-SHA256 salted password verification
- Secure cryptographically random session tokens
- Automatic session expiration (24h)
"""

import time
import secrets
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Any
from database import get_db_connection, hash_secret, verify_secret_hash
from config import OWNER_SESSION_DURATION_SECONDS

# In-memory active owner sessions: token -> {username, created_at, expires_at}
_ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}


def register_owner(username: str, password: str) -> Tuple[bool, str]:
    """Registers or creates an owner account."""
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters."

    now_iso = datetime.now(timezone.utc).isoformat()
    h, s = hash_secret(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO owners (username, password_hash, salt, status, created_at, updated_at)
               VALUES (?, ?, ?, 'ACTIVE', ?, ?)""",
            (username.strip(), h, s, now_iso, now_iso),
        )
        conn.commit()
        return True, "Owner account created successfully."
    except Exception as exc:
        conn.rollback()
        return False, f"Username already exists or database error: {str(exc)}"
    finally:
        conn.close()


def authenticate_owner(username: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Authenticates owner credentials.
    
    Returns: (success, session_token, message)
    """
    if not username or not password:
        return False, None, "Username and password are required."

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, salt, status FROM owners WHERE username = ?;",
        (username.strip(),),
    )
    owner = cursor.fetchone()
    conn.close()

    if not owner:
        return False, None, "Invalid owner credentials."

    if owner["status"] != "ACTIVE":
        return False, None, "Owner account is currently deactivated."

    if not verify_secret_hash(password, owner["password_hash"], owner["salt"]):
        return False, None, "Invalid owner credentials."

    # Create new session token
    token = secrets.token_urlsafe(32)
    now = time.time()
    _ACTIVE_SESSIONS[token] = {
        "username": owner["username"],
        "owner_id": owner["id"],
        "created_at": now,
        "expires_at": now + OWNER_SESSION_DURATION_SECONDS,
    }

    return True, token, "Owner authenticated successfully."


def verify_owner_session(session_token: Optional[str]) -> Optional[str]:
    """Validates an active session token. Returns username if valid, else None."""
    if not session_token:
        return None

    session = _ACTIVE_SESSIONS.get(session_token)
    if not session:
        return None

    if time.time() > session["expires_at"]:
        _ACTIVE_SESSIONS.pop(session_token, None)
        return None

    return session["username"]


def revoke_owner_session(session_token: Optional[str]) -> bool:
    """Logs out and revokes the active session token."""
    if session_token and session_token in _ACTIVE_SESSIONS:
        _ACTIVE_SESSIONS.pop(session_token, None)
        return True
    return False


def get_owner_count() -> int:
    """Returns total registered owner accounts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM owners;")
    row = cursor.fetchone()
    conn.close()
    return row["cnt"] if row else 0
