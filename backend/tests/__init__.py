"""Test-only credentials and an isolated database for the unittest suite."""

import os
import tempfile
from pathlib import Path

_TEST_DATA_DIR = tempfile.TemporaryDirectory(prefix="agentic-pqc-tests-")
os.environ["DATABASE_PATH"] = str(Path(_TEST_DATA_DIR.name) / "smart_door.db")
os.environ["DEVICE_SECRET"] = "test-device-token-not-a-secret"
os.environ["OWNER_INITIAL_PASSWORD"] = "test-owner-password"
os.environ["INITIAL_DOOR_PIN"] = "1234"
os.environ["INITIAL_SECONDARY_DOOR_PIN"] = "5678"
os.environ["GOOGLE_SCRIPT_URL"] = ""
os.environ["GOOGLE_SPREADSHEET_ID"] = ""
os.environ["GOOGLE_DEVICE_TOKEN"] = ""
