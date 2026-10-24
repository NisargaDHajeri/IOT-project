/*
 ==============================================================================
  AGENTIC AI-DRIVEN ADAPTIVE POST-QUANTUM SMART DOOR LOCK (ALL-IN-ONE)
  Hardware Node Firmware: NodeMCU ESP8266 + 4x4 Matrix Keypad + Buzzer
 ==============================================================================
*/

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>
#include <Keypad.h>
#include <bearssl/bearssl_hash.h>

// ==============================================================================
// 1. CONFIGURATION & PIN DEFINITIONS
// ==============================================================================
#define DEVICE_ID           "DOOR-001"
#define FIRMWARE_VERSION    "1.0.0"
#define API_VERSION         "3.0"

// Keypad Rows (Outputs during scan) - Universal GPIO Numbers
#define PIN_KEYPAD_R1       5   // NodeMCU D1 (GPIO 5)
#define PIN_KEYPAD_R2       4   // NodeMCU D2 (GPIO 4)
#define PIN_KEYPAD_R3       14  // NodeMCU D5 (GPIO 14)
#define PIN_KEYPAD_R4       12  // NodeMCU D6 (GPIO 12)

// Keypad Columns (Inputs with internal pullups) - Universal GPIO Numbers
#define PIN_KEYPAD_C1       13  // NodeMCU D7 (GPIO 13)
#define PIN_KEYPAD_C2       0   // NodeMCU D3 (GPIO 0)
#define PIN_KEYPAD_C3       2   // NodeMCU D4 (GPIO 2)
#define PIN_KEYPAD_C4       15  // NodeMCU D8 (GPIO 15)

// Audio Feedback Pin
#define PIN_BUZZER          16  // NodeMCU D0 (GPIO 16)

#define KEYPAD_ROWS         4
#define KEYPAD_COLS         4

#define UNLOCK_DURATION_MS          5000   // Door open window before auto-relock
#define LOCKOUT_DURATION_MS         60000  // High-risk lockout timeout
#define STATUS_REPORT_INTERVAL_MS   15000  // Device telemetry reporting interval
#define HTTP_TIMEOUT_MS             8000   // LAN API connection timeout
#define MAX_PIN_LENGTH              8      // Max digits in PIN buffer

// ==============================================================================
// 2. NETWORK CREDENTIALS & SECRETS (UPDATE BEFORE UPLOADING)
// ==============================================================================
const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// Set this to the Windows computer's Wi-Fi IPv4 address before uploading.
const char* DEVICE_API_BASE_URL = "http://192.168.1.100:5000";

// Shared Secret Device Token (must match backend .env)
const char* DEVICE_TOKEN = "SET_THE_SAME_RANDOM_DEVICE_SECRET_AS_BACKEND_ENV";

// ==============================================================================
// 3. KEYPAD SETUP
// ==============================================================================
const byte ROWS = 4;
const byte COLS = 4;

char keys[ROWS][COLS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};

byte rowPins[ROWS] = {PIN_KEYPAD_R1, PIN_KEYPAD_R2, PIN_KEYPAD_R3, PIN_KEYPAD_R4};
byte colPins[COLS] = {PIN_KEYPAD_C1, PIN_KEYPAD_C2, PIN_KEYPAD_C3, PIN_KEYPAD_C4};

Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

enum DoorState {
  STATE_BOOT,
  STATE_WIFI_CONNECTING,
  STATE_LOCKED,
  STATE_PASSWORD_ENTRY,
  STATE_AUTHENTICATING,
  STATE_LOCKOUT,
  STATE_RESET_WAITING_OTP,
  STATE_RESET_NEW_PIN,
  STATE_RESET_CONFIRM_PIN,
  STATE_ERROR
};

DoorState currentState = STATE_BOOT;
String pinBuffer = "";
String newPinBuffer = "";
String confirmPinBuffer = "";
unsigned long lastHeartbeatTime = 0;
unsigned long lastCommandPollTime = 0;
const unsigned long COMMAND_POLL_INTERVAL_MS = 3000;
unsigned long lockoutStartTime = 0;
unsigned long lockoutDurationMs = 60000;

void beepShort() {
  digitalWrite(PIN_BUZZER, HIGH);
  delay(40);
  digitalWrite(PIN_BUZZER, LOW);
}

void beepSuccess() {
  digitalWrite(PIN_BUZZER, HIGH);
  delay(100);
  digitalWrite(PIN_BUZZER, LOW);
  delay(80);
  digitalWrite(PIN_BUZZER, HIGH);
  delay(120);
  digitalWrite(PIN_BUZZER, LOW);
}

void beepFailure() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(PIN_BUZZER, HIGH);
    delay(120);
    digitalWrite(PIN_BUZZER, LOW);
    delay(80);
  }
}

void beepWarning() {
  for (int i = 0; i < 2; i++) {
    digitalWrite(PIN_BUZZER, HIGH);
    delay(200);
    digitalWrite(PIN_BUZZER, LOW);
    delay(100);
  }
}

void beepAlarm() {
  for (int i = 0; i < 4; i++) {
    digitalWrite(PIN_BUZZER, HIGH);
    delay(300);
    digitalWrite(PIN_BUZZER, LOW);
    delay(100);
  }
}

String computeSha256(const String& input) {
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, input.c_str(), input.length());
  
  unsigned char out[32];
  br_sha256_out(&ctx, out);

  char hexString[65];
  for (int i = 0; i < 32; i++) {
    sprintf(&hexString[i * 2], "%02x", out[i]);
  }
  hexString[64] = '\0';
  return String(hexString);
}

String apiUrl(const String& path) {
  return String(DEVICE_API_BASE_URL) + path;
}

String sendJsonPost(const String& path, const String& jsonPayload) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WIFI] Disconnected from network.");
    return "";
  }

  WiFiClient client;
  client.setTimeout(HTTP_TIMEOUT_MS);

  HTTPClient http;
  if (!http.begin(client, apiUrl(path))) {
    Serial.println("[API] Connection failed to initialize.");
    return "";
  }

  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Token", DEVICE_TOKEN);

  int httpCode = http.POST(jsonPayload);
  String response = "";

  if (httpCode > 0) {
    response = http.getString();
    Serial.printf("[API] HTTP status: %d\n", httpCode);
  } else {
    Serial.printf("[API] POST error code: %d (%s)\n", httpCode, http.errorToString(httpCode).c_str());
  }

  http.end();
  return response;
}

String sendJsonGet(const String& path) {
  WiFiClient client;
  client.setTimeout(HTTP_TIMEOUT_MS);
  HTTPClient http;
  if (!http.begin(client, apiUrl(path))) return "";
  http.addHeader("X-Device-Token", DEVICE_TOKEN);
  int httpCode = http.GET();
  String response = httpCode > 0 ? http.getString() : "";
  http.end();
  return response;
}

void reportHeartbeat() {
  Serial.println("[CLOUD] Sending heartbeat...");
  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  payload += "\"firmware_version\":\"" + String(FIRMWARE_VERSION) + "\",";
  payload += "\"ip_address\":\"" + WiFi.localIP().toString() + "\",";
  payload += "\"rssi\":" + String(WiFi.RSSI()) + ",";
  payload += "\"wifi_status\":\"CONNECTED\",";
  payload += "\"device_state\":\"" + String(currentState == STATE_LOCKOUT ? "LOCKOUT" : (currentState == STATE_PASSWORD_ENTRY ? "PASSWORD_ENTRY" : "LOCKED")) + "\",";
  payload += "\"input_length\":" + String(pinBuffer.length()) + ",";
  payload += "\"keypad_state\":\"" + String(pinBuffer.length() > 0 ? "INPUT" : "IDLE") + "\"";
  payload += "}";

  String resp = sendJsonPost("/api/device/heartbeat", payload);
  if (resp.indexOf("\"status\":\"OK\"") >= 0) {
    Serial.println("[DEVICE] Heartbeat accepted.");
  } else {
    Serial.println("[DEVICE] Heartbeat pending.");
  }
}

void reportKeypadActivity(int inputLength, const char* action) {
  if (WiFi.status() != WL_CONNECTED) return;

  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  payload += "\"firmware_version\":\"" + String(FIRMWARE_VERSION) + "\",";
  payload += "\"ip_address\":\"" + WiFi.localIP().toString() + "\",";
  payload += "\"rssi\":" + String(WiFi.RSSI()) + ",";
  payload += "\"wifi_status\":\"CONNECTED\",";
  payload += "\"device_state\":\"" + String(currentState == STATE_LOCKOUT ? "LOCKOUT" : (currentState == STATE_PASSWORD_ENTRY ? "PASSWORD_ENTRY" : "LOCKED")) + "\",";
  payload += "\"input_length\":" + String(inputLength) + ",";
  payload += "\"keypad_state\":\"" + String(action) + "\"";
  payload += "}";

  sendJsonPost("/api/device/keypad-activity", payload);
}

void acknowledgeCommand(const String& cmdId) {
  if (cmdId.length() == 0) return;
  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  payload += "\"command_id\":\"" + cmdId + "\"";
  payload += "}";
  sendJsonPost("/api/device/commands/" + cmdId + "/ack", payload);
}

void checkPendingCommands() {
  String resp = sendJsonGet("/api/device/commands?device_id=" + String(DEVICE_ID));
  if (resp.length() == 0 || resp.indexOf("\"count\":0") >= 0) {
    return;
  }

  // Extract command_id
  String cmdId = "";
  int idIdx = resp.indexOf("\"command_id\":\"");
  if (idIdx >= 0) {
    int idStart = idIdx + 14;
    int idEnd = resp.indexOf("\"", idStart);
    if (idEnd > idStart) {
      cmdId = resp.substring(idStart, idEnd);
    }
  }

  // Extract command name
  String cmdName = "";
  int cmdIdx = resp.indexOf("\"command\":\"");
  if (cmdIdx >= 0) {
    int cmdStart = cmdIdx + 11;
    int cmdEnd = resp.indexOf("\"", cmdStart);
    if (cmdEnd > cmdStart) {
      cmdName = resp.substring(cmdStart, cmdEnd);
    }
  }

  Serial.printf("[COMMAND] Received: %s (ID: %s)\n", cmdName.c_str(), cmdId.c_str());

  if (cmdName == "AUTHENTICATION_SUCCESS" || cmdName == "UNLOCK") {
    Serial.println("[AGENT] Decision: ALLOW (Simulated Door Unlocked)");
    beepSuccess();
    currentState = STATE_LOCKED;
  } else if (cmdName == "LOCK_AUTHENTICATION" || cmdName == "LOCKOUT") {
    Serial.println("[RISK] Intrusion Lockout Active!");
    beepAlarm();
    currentState = STATE_LOCKOUT;
    lockoutStartTime = millis();
  } else if (cmdName == "INCREASE_MONITORING") {
    Serial.println("[RISK] Suspicious attempt: Increased Monitoring.");
    beepWarning();
  } else if (cmdName == "AUTHENTICATION_FAILURE" || cmdName == "DENY") {
    Serial.println("[AUTH] Access Denied: Incorrect PIN.");
    beepFailure();
  } else if (cmdName == "OTP_VALID") {
    Serial.println("[OTP] OTP Verified by Cloud!");
    Serial.println("[RESET] Enter New Door PIN (4-8 digits, then #):");
    beepSuccess();
    currentState = STATE_RESET_NEW_PIN;
    pinBuffer = "";
  } else if (cmdName == "OTP_INVALID") {
    Serial.println("[OTP] OTP Invalid or Expired.");
    beepFailure();
    currentState = STATE_RESET_WAITING_OTP;
    pinBuffer = "";
  } else if (cmdName == "PASSWORD_UPDATED") {
    Serial.println("[RESET] Password updated successfully in SQLite!");
    beepSuccess();
    currentState = STATE_LOCKED;
    pinBuffer = "";
  } else if (cmdName == "RESET_WAITING_OTP") {
    Serial.println("[RESET] Cloud acknowledged AABB reset request. Awaiting OTP.");
    currentState = STATE_RESET_WAITING_OTP;
  }

  if (cmdId.length() > 0) {
    acknowledgeCommand(cmdId);
    Serial.println("[COMMAND] Acknowledged.");
  }
}

void processAuthentication(const String& pin) {
  Serial.println("[AUTH] Authenticating credential...");
  String hashValue = computeSha256(pin);

  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  payload += "\"pin_hash\":\"" + hashValue + "\",";
  payload += "\"ip_address\":\"" + WiFi.localIP().toString() + "\",";
  payload += "\"rssi\":" + String(WiFi.RSSI()) + "";
  payload += "}";

  String resp = sendJsonPost("/api/device/authenticate", payload);

  if (resp.indexOf("QUEUED_FOR_AGENT") >= 0 || resp.indexOf("SUCCESS") >= 0 || resp.indexOf("ALLOW") >= 0) {
    Serial.println("[EVENT] Event queued for LangGraph & Random Forest evaluation.");
  } else if (resp.indexOf("LOCKOUT") >= 0 || resp.indexOf("HIGH") >= 0) {
    Serial.println("[RISK] High Risk Intrusion Detected! Engaging LOCKOUT.");
    beepAlarm();
    currentState = STATE_LOCKOUT;
    lockoutStartTime = millis();
  } else {
    Serial.println("[AUTH] Event dispatched to cloud bridge.");
  }
}

void triggerAabbReset() {
  Serial.println("[RESET] 'AABB' Keypad Sequence Detected!");
  Serial.println("[RESET] State: ENTER 6-DIGIT OWNER OTP (from /owner)");
  beepWarning();

  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\"";
  payload += "}";

  sendJsonPost("/api/device/reset/request", payload);

  currentState = STATE_RESET_WAITING_OTP;
  pinBuffer = "";
}

void verifyOtpAndProceed(const String& otp) {
  Serial.println("[OTP] Verifying Owner OTP with Backend...");

  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  payload += "\"otp\":\"" + otp + "\"";
  payload += "}";

  String resp = sendJsonPost("/api/device/reset/verify-otp", payload);

  if (resp.indexOf("\"success\":true") >= 0) {
    Serial.println("[OTP] OTP verified. Enter new door PIN (4-8 digits, then #).");
    beepSuccess();
    currentState = STATE_RESET_NEW_PIN;
    pinBuffer = "";
  } else {
    Serial.println("[OTP] Error dispatching OTP.");
    beepFailure();
  }
}

void commitPasswordReset(const String& newPin, const String& confirmPin) {
  if (newPin != confirmPin) {
    Serial.println("[RESET] Password confirmation mismatch. Reset cancelled.");
    beepFailure();
    currentState = STATE_LOCKED;
    return;
  }

  Serial.println("[RESET] Committing New Door PIN to Backend SQLite...");

  String payload = "{";
  payload += "\"device_id\":\"" + String(DEVICE_ID) + "\",";
  payload += "\"new_pin_hash\":\"" + computeSha256(newPin) + "\",";
  payload += "\"confirm_pin_hash\":\"" + computeSha256(confirmPin) + "\"";
  payload += "}";

  String resp = sendJsonPost("/api/device/reset/set-password", payload);

  if (resp.indexOf("QUEUED_FOR_AGENT") >= 0 || resp.indexOf("success") >= 0) {
    Serial.println("[RESET] Password update request queued.");
  } else {
    Serial.println("[RESET] Password update failed.");
    beepFailure();
  }

  currentState = STATE_LOCKED;
  pinBuffer = "";
  newPinBuffer = "";
  confirmPinBuffer = "";
}

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println();
  Serial.println("==============================================================");
  Serial.println("  AGENTIC AI ADAPTIVE POST-QUANTUM SMART DOOR LOCK");
  Serial.println("  Hardware Node Terminal Initializing...");
  Serial.println("==============================================================");

  pinMode(PIN_BUZZER, OUTPUT);
  digitalWrite(PIN_BUZZER, LOW);
  beepShort();

  currentState = STATE_WIFI_CONNECTING;
  Serial.printf("[WIFI] Connecting to SSID: %s\n", WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 25) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[WIFI] Connected! IP Address: %s (RSSI: %d dBm)\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());
    beepSuccess();
    reportHeartbeat();
  } else {
    Serial.println("[WIFI] Connection failed. Operating in offline failsafe mode.");
    beepWarning();
  }

  currentState = STATE_LOCKED;
  Serial.println("[LOCK] Initial State: LOCKED. Ready for Keypad Input.");
}

void loop() {
  if (currentState == STATE_LOCKOUT) {
    if (millis() - lockoutStartTime >= lockoutDurationMs) {
      Serial.println("[LOCK] Security Lockout Period Expired. Restoring normal state.");
      currentState = STATE_LOCKED;
      pinBuffer = "";
    }
  }

  // Periodic Heartbeat
  if (millis() - lastHeartbeatTime >= STATUS_REPORT_INTERVAL_MS) {
    lastHeartbeatTime = millis();
    reportHeartbeat();
  }

  // Periodic Command Polling
  if (millis() - lastCommandPollTime >= COMMAND_POLL_INTERVAL_MS) {
    lastCommandPollTime = millis();
    checkPendingCommands();
  }

  char key = keypad.getKey();
  if (key) {
    beepShort();

    if (currentState == STATE_LOCKED || currentState == STATE_PASSWORD_ENTRY) {
      if (key == 'A' || key == 'B') {
        pinBuffer += key;
        if (pinBuffer.endsWith("AABB")) {
          triggerAabbReset();
          return;
        }
      }
    }

    switch (currentState) {
      case STATE_LOCKED:
      case STATE_PASSWORD_ENTRY:
        if (key == '#') {
          if (pinBuffer.length() > 0) {
            currentState = STATE_AUTHENTICATING;
            reportKeypadActivity(0, "SUBMIT");
            processAuthentication(pinBuffer);
            pinBuffer = "";
          }
        } else if (key == '*') {
          pinBuffer = "";
          reportKeypadActivity(0, "CLEAR");
          Serial.println("[KEYPAD] PIN Buffer Cleared (*)");
          beepShort();
        } else if (key >= '0' && key <= '9') {
          if (pinBuffer.length() < 8) {
            pinBuffer += key;
            currentState = STATE_PASSWORD_ENTRY;
            Serial.print("*");
            reportKeypadActivity(pinBuffer.length(), "INPUT");
          }
        }
        break;

      case STATE_RESET_WAITING_OTP:
        if (key == '#') {
          if (pinBuffer.length() >= 6) {
            reportKeypadActivity(0, "SUBMIT");
            verifyOtpAndProceed(pinBuffer);
          } else {
            Serial.println("[OTP] OTP must be 6 digits.");
            beepWarning();
          }
        } else if (key == '*') {
          pinBuffer = "";
          reportKeypadActivity(0, "CLEAR");
          Serial.println("[OTP] OTP Buffer Cleared.");
        } else if (key >= '0' && key <= '9') {
          if (pinBuffer.length() < 6) {
            pinBuffer += key;
            Serial.print("*");
            reportKeypadActivity(pinBuffer.length(), "INPUT");
          }
        }
        break;

      case STATE_RESET_NEW_PIN:
        if (key == '#') {
          if (pinBuffer.length() >= 4) {
            newPinBuffer = pinBuffer;
            pinBuffer = "";
            reportKeypadActivity(0, "SUBMIT");
            Serial.println();
            Serial.println("[RESET] Confirm New Password (then #):");
            beepShort();
            currentState = STATE_RESET_CONFIRM_PIN;
          } else {
            Serial.println("[RESET] PIN must be at least 4 digits.");
            beepWarning();
          }
        } else if (key == '*') {
          pinBuffer = "";
          reportKeypadActivity(0, "CLEAR");
        } else if (key >= '0' && key <= '9') {
          pinBuffer += key;
          Serial.print("*");
          reportKeypadActivity(pinBuffer.length(), "INPUT");
        }
        break;

      case STATE_RESET_CONFIRM_PIN:
        if (key == '#') {
          if (pinBuffer.length() >= 4) {
            confirmPinBuffer = pinBuffer;
            reportKeypadActivity(0, "SUBMIT");
            commitPasswordReset(newPinBuffer, confirmPinBuffer);
          }
        } else if (key == '*') {
          pinBuffer = "";
          reportKeypadActivity(0, "CLEAR");
        } else if (key >= '0' && key <= '9') {
          pinBuffer += key;
          Serial.print("*");
          reportKeypadActivity(pinBuffer.length(), "INPUT");
        }
        break;

      case STATE_LOCKOUT:
        Serial.println("[LOCKOUT] Keypad disabled during security lockout.");
        beepFailure();
        break;

      default:
        break;
    }
  }

  delay(20);
}
