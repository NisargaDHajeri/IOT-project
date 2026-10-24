"""Agentic PQC Smart Door Lock - Google Sheets Synchronizer Service.

Polls Google Sheets for new hardware events from the ESP8266, passes them
through the local Random Forest and LangGraph security reasoning pipeline,
and writes back adaptive PQC decisions and safe device commands.

Usage:
  python sync_google_sheets.py
  python sync_google_sheets.py --interval 3
  python sync_google_sheets.py --once
  python sync_google_sheets.py --dry-run
"""

import os
import sys
import time
import signal
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.google_sheets_bridge import GoogleSheetsBridge

# Configure logging with clear, professional formatting
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SyncGoogleSheets")


running = True

def signal_handler(sig, frame):
    global running
    logger.info("Shutdown signal received. Exiting synchronizer...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def main():
    parser = argparse.ArgumentParser(description="Agentic PQC Smart Door - Google Sheets Synchronizer")
    parser.add_argument("--interval", type=int, default=3, help="Polling interval in seconds (default: 3)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--dry-run", action="store_true", help="Test local pipeline with mock event")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    args = parser.parse_args()
    if os.getenv("ENABLE_GOOGLE_SHEETS_EXPORT", "").lower() not in {"1", "true", "yes"}:
        logger.info("Google Sheets synchronizer is disabled. Direct Flask REST is the operational transport.")
        return

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    print("=" * 72)
    print("AGENTIC AI ADAPTIVE PQC SMART DOOR LOCK - GOOGLE SHEETS SYNCHRONIZER")
    print("=" * 72)
    print(f"Polling Interval: {args.interval}s")
    print("Architecture    : ESP8266 -> Apps Script -> Google Sheets -> Synchronizer -> LangGraph")
    print("=" * 72)

    bridge = GoogleSheetsBridge()

    if args.dry_run:
        logger.info("Executing dry-run with simulated hardware events...")
        mock_success_event = {
            "device_id": "DOOR-001",
            "event_id": f"TEST-SUCCESS-{int(time.time())}",
            "pin_attempt_hash": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4", # 1234 (Dad)
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
        res1 = bridge.process_hardware_event(mock_success_event)
        logger.info(f"Dry-run 1 (Authorized): Status={res1.get('status')}, User={res1.get('decision', {}).get('user')}, Command={res1.get('command', {}).get('command')}")

        mock_failed_event = {
            "device_id": "DOOR-001",
            "event_id": f"TEST-FAIL-{int(time.time())}",
            "pin_attempt_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
        res2 = bridge.process_hardware_event(mock_failed_event)
        logger.info(f"Dry-run 2 (Unauthorized): Status={res2.get('status')}, Agent Risk={res2.get('decision', {}).get('agent_risk')}, Command={res2.get('command', {}).get('command')}")
        print("=" * 72)
        print("Dry-run completed successfully.")
        return

    if not bridge.is_configured():
        logger.warning(
            "Google Sheets is not yet configured in .env!\n"
            "  Please set GOOGLE_SCRIPT_URL or GOOGLE_SPREADSHEET_ID in .env.\n"
            "  See README.md for setup instructions.\n"
            "  Running in idle waiting mode..."
        )

    logger.info("Connected to local security engine. Synchronizer is active.")

    while running:
        try:
            processed = bridge.sync_once()
            if processed > 0:
                logger.info(f"Synchronized {processed} event(s).")
        except Exception as exc:
            logger.error(f"Error during synchronization cycle: {exc}")

        if args.once:
            break

        # Sleep for configured interval in small increments to respond to signals
        for _ in range(args.interval * 2):
            if not running:
                break
            time.sleep(0.5)

    logger.info("Synchronizer stopped.")


if __name__ == "__main__":
    main()
