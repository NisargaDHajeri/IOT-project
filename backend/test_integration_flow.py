import os
import requests
import sqlite3
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
OWNER_PASSWORD = os.environ.get("OWNER_INITIAL_PASSWORD")
if not OWNER_PASSWORD:
    raise RuntimeError("Set OWNER_INITIAL_PASSWORD in the project .env before running this integration script.")

# Step 0: Ensure clean security state
conn = sqlite3.connect('data/smart_door.db')
c = conn.cursor()
c.execute("UPDATE system_config SET config_val = '' WHERE config_key = 'lockout_until';")
c.execute("UPDATE system_config SET config_val = '0' WHERE config_key = 'active_failed_streak';")
c.execute("UPDATE system_config SET config_val = 'LOW' WHERE config_key = 'current_risk_level';")
c.execute("UPDATE system_config SET config_val = 'LOCKED' WHERE config_key = 'simulated_door_state';")
c.execute("UPDATE devices SET failed_attempts = 0, device_state = 'LOCKED';")
conn.commit()
conn.close()

base = 'http://127.0.0.1:5000'

s_owner = requests.Session()
# Login as owner
s_owner.post(f'{base}/api/owner/login', json={'username': 'admin', 'password': OWNER_PASSWORD})

# 1. Lock Door via Owner API
r = s_owner.post(f'{base}/api/door/lock')
door_status = requests.get(f'{base}/api/door/status').json()
owner_analytics = s_owner.get(f'{base}/api/owner/analytics').json()
print('1. Lock Door Test:')
print('   /door status door_state:', door_status.get('door_state'))
print('   /owner analytics door_state:', owner_analytics.get('door_state'))
assert door_status.get('door_state') == 'LOCKED', f"Expected LOCKED, got {door_status.get('door_state')}"
assert owner_analytics.get('door_state') == 'LOCKED', f"Expected LOCKED, got {owner_analytics.get('door_state')}"

# 2. Unlock Door via Owner API
r = s_owner.post(f'{base}/api/door/unlock')
door_status = requests.get(f'{base}/api/door/status').json()
owner_analytics = s_owner.get(f'{base}/api/owner/analytics').json()
print('2. Unlock Door Test:')
print('   /door status door_state:', door_status.get('door_state'))
print('   /owner analytics door_state:', owner_analytics.get('door_state'))
assert door_status.get('door_state') == 'OPEN', f"Expected OPEN, got {door_status.get('door_state')}"
assert owner_analytics.get('door_state') == 'OPEN', f"Expected OPEN, got {owner_analytics.get('door_state')}"

# 3. Authenticate with Dad PIN 1234
r = requests.post(f'{base}/api/authenticate', json={'password': '1234'})
auth_res = r.json()
door_status = requests.get(f'{base}/api/door/status').json()
print('3. Authenticate Dad (1234):')
print('   Auth Result:', auth_res.get('authenticated'), auth_res.get('user'))
print('   Door State:', door_status.get('door_state'))
print('   PQC Profile:', auth_res.get('security_profile', {}).get('kem'))
assert auth_res.get('authenticated') == True

# 4. Generate 6-Digit OTP from Owner
r = s_owner.post(f'{base}/api/reset/generate-otp')
otp_data = r.json()
otp = otp_data.get('otp')
print('4. Owner OTP Generation:')
print('   OTP:', otp, '| Length:', len(otp), '| Expires:', otp_data.get('expires_in_seconds'))
assert len(otp) == 6 and otp.isdigit()

# 5. Verify OTP
r = requests.post(f'{base}/api/reset/verify-otp', json={'otp': otp})
print('5. Verify OTP:')
print('   Success:', r.json().get('success'), r.json().get('message'))
assert r.json().get('success') == True

# 6. Set New PIN (4321)
r = requests.post(f'{base}/api/reset/set-password', json={'new_password': '4321', 'confirm_password': '4321'})
print('6. Set New PIN (4321):')
print('   Success:', r.json().get('success'), r.json().get('message'))
assert r.json().get('success') == True

# 7. Test Old PIN (1234) -> MUST FAIL
r_old = requests.post(f'{base}/api/authenticate', json={'password': '1234'})
print('7. Test Old PIN (1234):', 'FAIL (as expected)' if not r_old.json().get('authenticated') else 'UNEXPECTED PASS')
assert r_old.json().get('authenticated') == False

# 8. Test New PIN (4321) -> MUST PASS
r_new = requests.post(f'{base}/api/authenticate', json={'password': '4321'})
print('8. Test New PIN (4321):', 'PASS' if r_new.json().get('authenticated') else 'FAIL')
assert r_new.json().get('authenticated') == True

# 9. Restore PIN to 1234
r = s_owner.post(f'{base}/api/reset/generate-otp')
otp2 = r.json().get('otp')
requests.post(f'{base}/api/reset/verify-otp', json={'otp': otp2})
requests.post(f'{base}/api/reset/set-password', json={'new_password': '1234', 'confirm_password': '1234'})
print('9. Restored Default PIN to 1234')

print('\n>>> ALL 9 INTEGRATION CHECKS PASSED WITH 100% ACCURACY! <<<')
