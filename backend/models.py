"""Data models and serialization structures for Smart Door Lock System."""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime


@dataclass
class OwnerUser:
    id: int
    username: str
    status: str
    created_at: str
    updated_at: str


@dataclass
class DoorCredential:
    id: int
    credential_name: str
    version: int
    is_active: bool
    user_alias: str
    created_at: str
    updated_at: str


@dataclass
class DeviceStatus:
    device_id: str
    device_name: str
    firmware_version: str
    ip_address: str
    rssi: int
    wifi_status: str
    is_online: bool
    device_state: str
    failed_attempts: int
    last_seen: Optional[str]


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    severity: str
    event_type: str
    source: str
    description: str
    metadata: Dict[str, Any]


@dataclass
class ResetSession:
    session_id: str
    device_id: str
    status: str
    attempt_count: int
    max_attempts: int
    created_at: str
    expires_at: str
    verified_at: Optional[str]
    completed_at: Optional[str]
