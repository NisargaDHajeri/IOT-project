"""Google Sheets Bridge & Security Synchronizer Service.

Acts as the communication and security bridge between:
  Google Sheets / Google Apps Script <-> Local LangGraph Security Engine

Security Principles:
- Google Sheets acts purely as a transport bridge.
- The local Python backend is the authoritative security decision-maker.
- Event deduplication and idempotency are strictly enforced.
- Plaintext PINs are never stored or logged in Google Sheets.
"""

import os
import json
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from dotenv import load_dotenv

# Load local environment variables if present
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR.parent / ".env")
load_dotenv(BASE_DIR / ".env")

from database import get_db_connection
from services.authentication_service import authenticate_access
from services.device_service import update_device_heartbeat, get_device_status
from services.simulation_service import set_door_state
from services.otp_service import trigger_aabb_reset, verify_reset_otp, complete_password_reset
from services.audit_service import log_security_event, log_audit
from services.pqc_service import get_pqc_profile

logger = logging.getLogger("GoogleSheetsBridge")

PROCESSED_EVENTS_FILE = BASE_DIR / "data" / "processed_events.json"


class GoogleSheetsBridge:
    def __init__(
        self,
        script_url: Optional[str] = None,
        device_token: Optional[str] = None,
        spreadsheet_id: Optional[str] = None,
        credentials_file: Optional[str] = None,
        device_id: str = "DOOR-001",
    ):
        self.script_url = script_url or os.getenv("GOOGLE_SCRIPT_URL", "")
        self.device_token = device_token or os.getenv("GOOGLE_DEVICE_TOKEN", "")
        self.spreadsheet_id = spreadsheet_id or os.getenv("GOOGLE_SPREADSHEET_ID", "")
        self.credentials_file = credentials_file or os.getenv("GOOGLE_CREDENTIALS_FILE", "")
        self.device_id = device_id or os.getenv("DEVICE_ID", "DOOR-001")
        
        self.processed_ids = self._load_processed_ids()
        self.gspread_client = None

        # Attempt to initialize gspread if credentials file is present
        if self.credentials_file and os.path.exists(self.credentials_file) and self.spreadsheet_id:
            try:
                import gspread
                from google.oauth2.service_account import Credentials

                scopes = [
                    "https://www.googleapis.com/auth/spreadsheets",
                    "https://www.googleapis.com/auth/drive",
                ]
                creds = Credentials.from_service_account_file(self.credentials_file, scopes=scopes)
                self.gspread_client = gspread.authorize(creds)
                logger.info(f"[BRIDGE] Initialized direct gspread client for spreadsheet: {self.spreadsheet_id}")
            except Exception as exc:
                logger.warning(f"[BRIDGE] Could not initialize gspread (falling back to Web App mode): {exc}")

    def _load_processed_ids(self) -> set:
        if PROCESSED_EVENTS_FILE.exists():
            try:
                data = json.loads(PROCESSED_EVENTS_FILE.read_text(encoding="utf-8"))
                return set(data)
            except Exception:
                return set()
        return set()

    def _save_processed_id(self, event_id: str):
        self.processed_ids.add(event_id)
        PROCESSED_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Keep last 1000 IDs
        recent = list(self.processed_ids)[-1000:]
        PROCESSED_EVENTS_FILE.write_text(json.dumps(recent, indent=2), encoding="utf-8")

    def is_configured(self) -> bool:
        return bool(self.script_url) or (bool(self.gspread_client) and bool(self.spreadsheet_id))

    def _send_apps_script_post(self, payload: Dict[str, Any], timeout: int = 20) -> Optional[Dict[str, Any]]:
        """Sends a POST request to Google Apps Script Web App and resolves redirect safely without timeout."""
        if not self.script_url:
            return None

        if "token" not in payload and self.device_token:
            payload["token"] = self.device_token

        # Google Apps Script responds to POST with HTTP 302 Found redirecting to script.googleusercontent.com/macros/echo
        # In requests library, automatic redirect (allow_redirects=True) sends a POST to the echo URL which hangs / 404s.
        # Handling the redirect manually and fetching the echo location via GET retrieves the JSON immediately (2-3s).
        resp = requests.post(self.script_url, json=payload, allow_redirects=False, timeout=timeout)
        
        if resp.status_code in (301, 302, 303, 307, 308):
            redirect_url = resp.headers.get("Location")
            if redirect_url:
                resp = requests.get(redirect_url, timeout=timeout)
        
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.warning(f"[BRIDGE] Apps Script HTTP status: {resp.status_code} ({resp.text[:120]})")
            return None

    def fetch_and_sync_device_status(self) -> Optional[Dict[str, Any]]:
        """Fetches latest device status from cloud and synchronizes local SQLite devices table."""
        if not self.script_url:
            return None

        try:
            payload = {
                "action": "get_status",
                "token": self.device_token,
                "device_id": self.device_id,
            }
            data = self._send_apps_script_post(payload, timeout=20)
            if data and data.get("success"):
                wifi_status = data.get("wifi_status", "DISCONNECTED")
                ip_address = data.get("ip_address", "—")
                rssi = int(data.get("rssi") or 0)
                dev_state = data.get("device_state", "LOCKED")
                raw_len = data.get("input_length")
                input_length = int(raw_len) if raw_len is not None else 0
                keypad_state = str(data.get("keypad_state") or ("INPUT" if input_length > 0 else "IDLE"))
                
                # Update local database
                update_device_heartbeat(
                    device_id=self.device_id,
                    ip_address=ip_address,
                    rssi=rssi,
                    wifi_status=wifi_status,
                    device_state=dev_state,
                    input_length=input_length,
                    keypad_state=keypad_state,
                )
                return data
        except Exception as exc:
            logger.debug(f"[BRIDGE] Status sync jitter: {exc}")
        return None

    def fetch_unprocessed_events(self) -> List[Dict[str, Any]]:
        """Fetch unhandled events from Google Sheets or Apps Script Web App."""
        if not self.is_configured():
            return []

        # 1. Primary Method: Google Apps Script Web App API
        if self.script_url:
            try:
                payload = {
                    "action": "get_unprocessed_events",
                    "token": self.device_token,
                    "device_id": self.device_id,
                }
                data = self._send_apps_script_post(payload, timeout=20)
                if data:
                    if data.get("success"):
                        events = data.get("events", [])
                        return [e for e in events if e.get("event_id") not in self.processed_ids]
                    else:
                        logger.warning(f"[BRIDGE] Apps Script error fetching events: {data.get('error')}")
            except Exception as exc:
                logger.error(f"[BRIDGE] Failed to fetch events from Apps Script: {exc}")

        # 2. Secondary Method: Direct gspread API
        if self.gspread_client and self.spreadsheet_id:
            try:
                sheet = self.gspread_client.open_by_key(self.spreadsheet_id)
                events_ws = sheet.worksheet("EVENTS")
                records = events_ws.get_all_records()
                unprocessed = []
                for idx, row in enumerate(records, start=2):
                    event_id = str(row.get("event_id", ""))
                    auth_result = str(row.get("authentication_result", "")).strip()
                    if event_id and not auth_result and event_id not in self.processed_ids:
                        row["_row_number"] = idx
                        unprocessed.append(row)
                return unprocessed
            except Exception as exc:
                logger.error(f"[BRIDGE] Failed to fetch events via gspread: {exc}")

        return []

    def process_hardware_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single hardware event through the full backend architecture."""
        event_id = event_data.get("event_id")
        if not event_id:
            raise ValueError("Event must contain a valid event_id.")

        if event_id in self.processed_ids:
            logger.info(f"[BRIDGE] Event {event_id} already processed. Skipping duplicate.")
            return {"status": "SKIPPED_DUPLICATE", "event_id": event_id}

        event_type = event_data.get("event_type", "AUTH_ATTEMPT")
        device_id = event_data.get("device_id", self.device_id)
        pin_hash = event_data.get("pin_attempt_hash") or event_data.get("pin_hash") or event_data.get("pin_attempt") or ""
        event_timestamp = event_data.get("timestamp") or datetime.now(timezone.utc).isoformat()

        logger.info(f"[BRIDGE] Event received: {event_id} ({event_type}) from {device_id}")

        # ======================================================================
        # BRANCH 1: AABB PASSWORD RESET REQUEST
        # ======================================================================
        if event_type == "RESET_REQUEST":
            logger.info(f"[RESET] Physical keypad AABB reset initiated for {device_id}")
            res = trigger_aabb_reset(device_id)
            log_security_event(
                severity="INFO",
                event_type="PASSWORD_RESET_INITIATED",
                source="ESP8266_KEYPAD",
                description="AABB reset initiated from physical keypad. Awaiting Owner OTP.",
            )
            command = {
                "command_id": f"CMD-{event_id}",
                "device_id": device_id,
                "command": "RESET_WAITING_OTP",
                "risk": "LOW",
                "reason": "AABB reset detected. Awaiting OTP.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            decision_payload = {
                "event_id": event_id,
                "device_id": device_id,
                "authentication_result": "RESET_INITIATED",
                "user": "RESET_FLOW",
                "ml_risk": "LOW",
                "ml_confidence": "{}",
                "agent_risk": "LOW",
                "escalated": "NO",
                "pqc_kem": "ML-KEM-512",
                "pqc_signature": "ML-DSA-44",
                "action": "RESET_WAITING_OTP",
                "reason": "AABB detected. Enter 6-digit Owner OTP.",
                "device_status": "PROCESSED",
            }

        # ======================================================================
        # BRANCH 2: VERIFY 6-DIGIT OWNER OTP
        # ======================================================================
        elif event_type == "VERIFY_OTP":
            otp = event_data.get("otp") or pin_hash
            logger.info(f"[OTP] Verifying 6-digit OTP from physical keypad for {device_id}")
            ok, msg = verify_reset_otp(device_id, otp)
            cmd_name = "OTP_VALID" if ok else "OTP_INVALID"
            log_security_event(
                severity="INFO" if ok else "MEDIUM",
                event_type="RESET_OTP_VERIFIED" if ok else "RESET_OTP_FAILED",
                source="ESP8266_KEYPAD",
                description=f"Physical keypad OTP verification: {msg}",
            )
            command = {
                "command_id": f"CMD-{event_id}",
                "device_id": device_id,
                "command": cmd_name,
                "risk": "LOW" if ok else "MEDIUM",
                "reason": msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            decision_payload = {
                "event_id": event_id,
                "device_id": device_id,
                "authentication_result": "SUCCESS" if ok else "FAILED",
                "user": "OWNER_OTP",
                "ml_risk": "LOW" if ok else "MEDIUM",
                "ml_confidence": "{}",
                "agent_risk": "LOW" if ok else "MEDIUM",
                "escalated": "NO",
                "pqc_kem": "ML-KEM-512",
                "pqc_signature": "ML-DSA-44",
                "action": cmd_name,
                "reason": msg,
                "device_status": "PROCESSED",
            }

        # ======================================================================
        # BRANCH 3: SET NEW PASSWORD
        # ======================================================================
        elif event_type == "SET_PASSWORD":
            new_pin = event_data.get("new_pin") or pin_hash
            confirm_pin = event_data.get("confirm_pin") or new_pin
            logger.info(f"[RESET] Committing new door PIN from keypad for {device_id}")
            ok, msg = complete_password_reset(device_id, new_pin, confirm_pin)
            cmd_name = "PASSWORD_UPDATED" if ok else "AUTHENTICATION_FAILURE"
            command = {
                "command_id": f"CMD-{event_id}",
                "device_id": device_id,
                "command": cmd_name,
                "risk": "LOW",
                "reason": msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            decision_payload = {
                "event_id": event_id,
                "device_id": device_id,
                "authentication_result": "SUCCESS" if ok else "FAILED",
                "user": "DAD",
                "ml_risk": "LOW",
                "ml_confidence": "{}",
                "agent_risk": "LOW",
                "escalated": "NO",
                "pqc_kem": "ML-KEM-512",
                "pqc_signature": "ML-DSA-44",
                "action": cmd_name,
                "reason": msg,
                "device_status": "PROCESSED",
            }

        # ======================================================================
        # BRANCH 4: STANDARD DOOR PIN AUTHENTICATION
        # ======================================================================
        else:
            logger.info(f"[AUTH] Processing PIN authentication event for {device_id}...")
            auth_res = authenticate_access(
                credential_input=pin_hash,
                source="ESP8266_KEYPAD",
                is_hash=True,
                device_id=device_id,
            )

            is_auth = auth_res.get("authenticated", False)
            user_name = auth_res.get("user", "UNKNOWN")
            final_risk = auth_res.get("risk_level", "LOW")
            ml_risk = auth_res.get("ml_risk_level", "LOW")
            pqc_prof = auth_res.get("security_profile", get_pqc_profile(final_risk))
            reasoning = auth_res.get("reasoning", ["Evaluated via LangGraph security pipeline."])

            if is_auth:
                cmd_name = "AUTHENTICATION_SUCCESS"
                reason_str = f"Authorized user {user_name} accepted."
                # Synchronize simulated door state to OPEN
                set_door_state("OPEN")
            else:
                if final_risk == "HIGH":
                    cmd_name = "LOCK_AUTHENTICATION"
                    reason_str = "Intrusion lockout engaged."
                    set_door_state("LOCKOUT")
                elif final_risk == "MEDIUM":
                    cmd_name = "INCREASE_MONITORING"
                    reason_str = "Suspicious activity detected."
                else:
                    cmd_name = "AUTHENTICATION_FAILURE"
                    reason_str = "Invalid PIN credential."

            command = {
                "command_id": f"CMD-{event_id}",
                "device_id": device_id,
                "command": cmd_name,
                "risk": final_risk,
                "reason": reason_str,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            decision_payload = {
                "event_id": event_id,
                "device_id": device_id,
                "authentication_result": "SUCCESS" if is_auth else "FAILED",
                "user": user_name,
                "ml_risk": ml_risk,
                "ml_confidence": "{}",
                "agent_risk": final_risk,
                "escalated": "YES" if final_risk in ["MEDIUM", "HIGH"] else "NO",
                "pqc_kem": pqc_prof.get("kem", "ML-KEM-512"),
                "pqc_signature": pqc_prof.get("signature", "ML-DSA-44"),
                "action": cmd_name,
                "reason": reason_str,
                "device_status": "PROCESSED",
            }

        # Write Decision & Command back to Cloud
        self._write_decision_to_cloud(decision_payload, command, event_data.get("_row_number"))

        # Mark as processed locally and clear any active keypad buffer
        self._save_processed_id(event_id)
        update_device_heartbeat(
            device_id=device_id,
            input_length=0,
            keypad_state="SUBMIT",
        )
        logger.info(f"[BRIDGE] Event {event_id} processed. Queued command: {command['command']}")

        return {
            "status": "SUCCESS",
            "event_id": event_id,
            "decision": decision_payload,
            "command": command,
        }

    def _write_decision_to_cloud(self, decision: Dict[str, Any], command: Dict[str, Any], row_number: Optional[int] = None):
        """Write back decision and command to Google Sheets / Apps Script."""
        if self.script_url:
            try:
                payload = {
                    "action": "sync_decision",
                    "token": self.device_token,
                    "decision": decision,
                    "command": command,
                }
                data = self._send_apps_script_post(payload, timeout=20)
                if data and data.get("success"):
                    logger.debug(f"[BRIDGE] Decision synced to Apps Script for event {decision['event_id']}")
                    return
                else:
                    err_msg = data.get("error") if data else "Empty response"
                    logger.warning(f"[BRIDGE] Apps Script sync_decision error: {err_msg}")
            except Exception as exc:
                logger.error(f"[BRIDGE] Failed to write decision to Apps Script: {exc}")

        if self.gspread_client and self.spreadsheet_id:
            try:
                sheet = self.gspread_client.open_by_key(self.spreadsheet_id)
                commands_ws = sheet.worksheet("COMMANDS")
                commands_ws.append_row([
                    command["timestamp"],
                    command["command_id"],
                    command["device_id"],
                    command["command"],
                    command["risk"],
                    command["reason"],
                    "NO",
                    "NO",
                ])
                logger.debug(f"[BRIDGE] Decision written via gspread for event {decision['event_id']}")
            except Exception as exc:
                logger.error(f"[BRIDGE] Failed to write decision via gspread: {exc}")

    def sync_once(self) -> int:
        """Run one synchronization iteration: sync telemetry and process pending events."""
        # 1. Sync device heartbeat & status
        self.fetch_and_sync_device_status()

        # 2. Fetch and process unprocessed events
        events = self.fetch_unprocessed_events()
        if not events:
            return 0
        
        logger.info(f"[BRIDGE] Found {len(events)} new hardware event(s) to process.")
        count = 0
        for evt in events:
            try:
                res = self.process_hardware_event(evt)
                if res.get("status") == "SUCCESS":
                    count += 1
            except Exception as exc:
                logger.error(f"[BRIDGE] Failed processing event {evt.get('event_id')}: {exc}")
        return count
