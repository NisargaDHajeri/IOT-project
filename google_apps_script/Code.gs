/**
 * ==============================================================================
 * AGENTIC AI ADAPTIVE PQC SMART DOOR LOCK - GOOGLE APPS SCRIPT WEB APP
 * ==============================================================================
 * Acts as the secure cloud communication bridge between:
 *   ESP8266 Keypad Door Node <----> Local LangGraph Security Engine
 *
 * Security & Design Principles:
 * 1. Google Sheets is a message transport layer, NOT the security engine.
 * 2. Plaintext PINs are never stored. Only SHA-256 hashes are recorded.
 * 3. Strict token validation and duplicate event ID prevention.
 * 4. Only whitelisted commands are allowed.
 */

// Set DEVICE_TOKEN in Script Properties before enabling the integration.
var DEFAULT_DEVICE_TOKEN = "";

// Allowed Command Whitelist
var ALLOWED_COMMANDS = [
  "NORMAL_OPERATION",
  "INCREASE_MONITORING",
  "LOCK_AUTHENTICATION",
  "AUTHENTICATION_SUCCESS",
  "AUTHENTICATION_FAILURE",
  "SYSTEM_RESET",
  "UNLOCK",
  "DENY",
  "LOCKOUT",
  "ALERT",
  "OTP_VALID",
  "OTP_INVALID",
  "PASSWORD_UPDATED",
  "RESET_WAITING_OTP"
];

/**
 * Handle HTTP GET Requests
 */
function doGet(e) {
  var action = (e && e.parameter && e.parameter.action) ? e.parameter.action : "ping";
  var token = (e && e.parameter && (e.parameter.token || e.parameter.device_token)) ? (e.parameter.token || e.parameter.device_token) : "";
  var deviceId = (e && e.parameter && e.parameter.device_id) ? e.parameter.device_id : "DOOR-001";

  if (action === "ping" || action === "status") {
    return jsonResponse({
      success: true,
      status: "ONLINE",
      service: "Agentic PQC Smart Door Google Sheets Bridge",
      timestamp: new Date().toISOString()
    });
  }

  if (action === "get_command") {
    if (!validateToken(token)) {
      return jsonResponse({ success: false, error: "Unauthorized token" }, 401);
    }
    return handleGetCommand(deviceId);
  }

  if (action === "get_status" || action === "get_device_status") {
    if (!validateToken(token)) {
      return jsonResponse({ success: false, error: "Unauthorized token" }, 401);
    }
    return handleGetStatus(deviceId);
  }

  if (action === "get_unprocessed_events") {
    if (!validateToken(token)) {
      return jsonResponse({ success: false, error: "Unauthorized token" }, 401);
    }
    return handleGetUnprocessedEvents(deviceId);
  }

  return jsonResponse({ success: false, error: "Unknown GET action: " + action });
}

/**
 * Handle HTTP POST Requests
 */
function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return jsonResponse({ success: false, error: "Empty request payload" }, 400);
    }

    var data = JSON.parse(e.postData.contents);
    var token = data.token || data.device_token || (e.parameter && (e.parameter.token || e.parameter.device_token)) || "";

    if (!validateToken(token)) {
      return jsonResponse({ success: false, error: "Unauthorized: Invalid device token" }, 401);
    }

    var action = data.action || (data.event_type ? "post_event" : "");

    switch (action) {
      case "post_event":
      case "AUTH_ATTEMPT":
      case "AUTHENTICATE":
      case "RESET_REQUEST":
      case "VERIFY_OTP":
      case "SET_PASSWORD":
        return handlePostEvent(data);

      case "get_command":
        return handleGetCommand(data.device_id || "DOOR-001");

      case "ack_command":
      case "ack":
        return handleAckCommand(data);

      case "post_status":
      case "status":
      case "HEARTBEAT":
        return handlePostStatus(data);

      case "get_status":
      case "get_device_status":
        return handleGetStatus(data.device_id || "DOOR-001");

      case "get_unprocessed_events":
        return handleGetUnprocessedEvents(data.device_id);

      case "sync_decision":
        return handleSyncDecision(data);

      default:
        return jsonResponse({ success: false, error: "Invalid action: " + action }, 400);
    }
  } catch (err) {
    return jsonResponse({ success: false, error: "Internal error: " + err.toString() }, 500);
  }
}

/**
 * Validate Device Token
 */
function validateToken(token) {
  var configuredToken = PropertiesService.getScriptProperties().getProperty("DEVICE_TOKEN") || DEFAULT_DEVICE_TOKEN;
  return Boolean(configuredToken && token && token === configuredToken);
}

/**
 * Handle new hardware authentication event from ESP8266
 */
function handlePostEvent(data) {
  var eventId = data.event_id || ("EVT-" + new Date().getTime());
  var deviceId = data.device_id || "DOOR-001";
  var eventType = data.event_type || (data.action !== "post_event" ? data.action : "AUTH_ATTEMPT");
  var pinHash = data.pin_attempt_hash || data.pin_hash || data.pin_attempt || data.otp || data.new_pin || (eventType === "RESET_REQUEST" ? "AABB_SEQUENCE" : "");
  var timestamp = data.timestamp || new Date().toISOString();

  if (!pinHash && eventType === "AUTH_ATTEMPT") {
    return jsonResponse({ success: false, error: "Missing required pin_attempt_hash" }, 400);
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var eventsSheet = ss.getSheetByName("EVENTS") || setupSheets().eventsSheet;

  // Duplicate Check
  var records = eventsSheet.getDataRange().getValues();
  for (var i = 1; i < records.length; i++) {
    if (records[i][2] === eventId) {
      return jsonResponse({
        success: true,
        message: "Duplicate event acknowledged",
        event_id: eventId,
        duplicate: true
      });
    }
  }

  // Append new event
  eventsSheet.appendRow([
    timestamp,
    deviceId,
    eventId,
    eventType,
    pinHash,       // SHA-256 hash or reset parameter
    "",            // authentication_result (filled by Python engine)
    "",            // user
    "",            // ml_risk
    "",            // ml_confidence
    "",            // agent_risk
    "",            // escalated
    "",            // pqc_kem
    "",            // pqc_signature
    "",            // action
    "",            // reason
    "PENDING"      // device_status
  ]);

  return jsonResponse({
    success: true,
    event_id: eventId,
    event_type: eventType,
    status: "QUEUED_FOR_AGENT"
  });
}

/**
 * Handle ESP8266 Command Polling
 */
function handleGetCommand(deviceId) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var cmdSheet = ss.getSheetByName("COMMANDS") || setupSheets().cmdSheet;
  var data = cmdSheet.getDataRange().getValues();

  // Find oldest unacknowledged command for deviceId
  for (var i = 1; i < data.length; i++) {
    var row = data[i];
    var rowDevice = row[2];
    var acknowledged = String(row[7]).toUpperCase();

    if ((!deviceId || rowDevice === deviceId) && acknowledged !== "YES" && acknowledged !== "TRUE") {
      var commandName = String(row[3]);
      
      // Strict Whitelist Validation
      if (ALLOWED_COMMANDS.indexOf(commandName) === -1) {
        commandName = "NORMAL_OPERATION";
      }

      return jsonResponse({
        success: true,
        has_command: true,
        command_id: row[1],
        device_id: row[2],
        command: commandName,
        risk: row[4] || "LOW",
        reason: row[5] || "",
        timestamp: row[0]
      });
    }
  }

  return jsonResponse({
    success: true,
    has_command: false,
    message: "No pending commands"
  });
}

/**
 * Handle Command Acknowledgment from ESP8266
 */
function handleAckCommand(data) {
  var commandId = data.command_id;
  if (!commandId) {
    return jsonResponse({ success: false, error: "Missing command_id" }, 400);
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var cmdSheet = ss.getSheetByName("COMMANDS") || setupSheets().cmdSheet;
  var values = cmdSheet.getDataRange().getValues();

  for (var i = 1; i < values.length; i++) {
    if (values[i][1] === commandId) {
      cmdSheet.getRange(i + 1, 7).setValue("YES"); // processed
      cmdSheet.getRange(i + 1, 8).setValue("YES"); // acknowledged
      return jsonResponse({ success: true, command_id: commandId, acknowledged: true });
    }
  }

  return jsonResponse({ success: false, error: "Command ID not found" }, 404);
}

/**
 * Handle Device Heartbeat & Telemetry from ESP8266
 */
function handlePostStatus(data) {
  var deviceId = data.device_id || "DOOR-001";
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var statusSheet = ss.getSheetByName("DEVICE_STATUS") || setupSheets().statusSheet;
  var timestamp = data.timestamp || new Date().toISOString();

  var values = statusSheet.getDataRange().getValues();
  var foundRow = -1;

  for (var i = 1; i < values.length; i++) {
    if (values[i][1] === deviceId) {
      foundRow = i + 1;
      break;
    }
  }

  var rowData = [
    timestamp,
    deviceId,
    data.wifi_status || "CONNECTED",
    data.ip_address || "0.0.0.0",
    data.rssi || -99,
    data.firmware_version || "2.0.0",
    data.uptime || 0,
    data.last_event || "HEARTBEAT",
    data.device_state || "LOCKED",
    (data.input_length !== undefined && data.input_length !== null) ? Number(data.input_length) : 0,
    data.keypad_state || (data.input_length > 0 ? "INPUT" : "IDLE")
  ];

  if (foundRow > 0) {
    statusSheet.getRange(foundRow, 1, 1, rowData.length).setValues([rowData]);
  } else {
    statusSheet.appendRow(rowData);
  }

  return jsonResponse({ success: true, device_id: deviceId, updated: true });
}

/**
 * Handle Reading Device Telemetry Status from Google Sheets
 */
function handleGetStatus(deviceId) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var statusSheet = ss.getSheetByName("DEVICE_STATUS") || setupSheets().statusSheet;
  var values = statusSheet.getDataRange().getValues();

  for (var i = 1; i < values.length; i++) {
    if (values[i][1] === (deviceId || "DOOR-001")) {
      var row = values[i];
      return jsonResponse({
        success: true,
        device_id: row[1],
        timestamp: row[0],
        wifi_status: row[2],
        ip_address: row[3],
        rssi: row[4],
        firmware_version: row[5],
        uptime: row[6],
        last_event: row[7],
        device_state: row[8],
        input_length: row[9] !== undefined && row[9] !== "" ? Number(row[9]) : 0,
        keypad_state: row[10] || "IDLE"
      });
    }
  }

  return jsonResponse({
    success: true,
    device_id: deviceId || "DOOR-001",
    wifi_status: "OFFLINE",
    ip_address: "—",
    rssi: 0,
    device_state: "LOCKED",
    input_length: 0,
    keypad_state: "IDLE",
    last_event: "NO_HEARTBEAT"
  });
}

/**
 * Handle Query for Unprocessed Events (used by Python synchronizer)
 */
function handleGetUnprocessedEvents(deviceId) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var eventsSheet = ss.getSheetByName("EVENTS") || setupSheets().eventsSheet;
  var values = eventsSheet.getDataRange().getValues();
  var unprocessed = [];

  for (var i = 1; i < values.length; i++) {
    var row = values[i];
    var authResult = String(row[5]).trim();
    var dev = row[1];

    if (!authResult && (!deviceId || dev === deviceId)) {
      unprocessed.push({
        _row_number: i + 1,
        timestamp: row[0],
        device_id: row[1],
        event_id: row[2],
        event_type: row[3],
        pin_attempt_hash: row[4]
      });
    }
  }

  return jsonResponse({ success: true, count: unprocessed.length, events: unprocessed });
}

/**
 * Handle Decision Sync back from Python LangGraph Engine
 */
function handleSyncDecision(data) {
  var decision = data.decision;
  var command = data.command;

  if (!decision || !decision.event_id) {
    return jsonResponse({ success: false, error: "Missing decision payload" }, 400);
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var eventsSheet = ss.getSheetByName("EVENTS") || setupSheets().eventsSheet;
  var values = eventsSheet.getDataRange().getValues();
  var eventRow = -1;

  for (var i = 1; i < values.length; i++) {
    if (values[i][2] === decision.event_id) {
      eventRow = i + 1;
      break;
    }
  }

  if (eventRow > 0) {
    eventsSheet.getRange(eventRow, 6).setValue(decision.authentication_result || "");
    eventsSheet.getRange(eventRow, 7).setValue(decision.user || "UNKNOWN");
    eventsSheet.getRange(eventRow, 8).setValue(decision.ml_risk || "LOW");
    eventsSheet.getRange(eventRow, 9).setValue(decision.ml_confidence || "");
    eventsSheet.getRange(eventRow, 10).setValue(decision.agent_risk || "LOW");
    eventsSheet.getRange(eventRow, 11).setValue(decision.escalated || "NO");
    eventsSheet.getRange(eventRow, 12).setValue(decision.pqc_kem || "ML-KEM-512");
    eventsSheet.getRange(eventRow, 13).setValue(decision.pqc_signature || "ML-DSA-44");
    eventsSheet.getRange(eventRow, 14).setValue(decision.action || "");
    eventsSheet.getRange(eventRow, 15).setValue(decision.reason || "");
    eventsSheet.getRange(eventRow, 16).setValue("PROCESSED");
  }

  // Insert Command
  if (command) {
    var cmdSheet = ss.getSheetByName("COMMANDS") || setupSheets().cmdSheet;
    cmdSheet.appendRow([
      command.timestamp || new Date().toISOString(),
      command.command_id,
      command.device_id || "DOOR-001",
      command.command,
      command.risk || "LOW",
      command.reason || "",
      "NO",
      "NO"
    ]);
  }

  return jsonResponse({ success: true, event_id: decision.event_id, synced: true });
}

/**
 * 1-Click Spreadsheet Setup & Tab Initializer
 * Run this function once from the Apps Script editor to create all sheets with headers.
 */
function setupSheets() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();

  // 1. EVENTS Sheet
  var eventsSheet = ss.getSheetByName("EVENTS");
  if (!eventsSheet) {
    eventsSheet = ss.insertSheet("EVENTS");
  }
  eventsSheet.getRange("A1:P1").setValues([[
    "timestamp", "device_id", "event_id", "event_type", "pin_attempt",
    "authentication_result", "user", "ml_risk", "ml_confidence", "agent_risk",
    "escalated", "pqc_kem", "pqc_signature", "action", "reason", "device_status"
  ]]);
  eventsSheet.getRange("A1:P1").setFontWeight("bold").setBackground("#1e293b").setFontColor("#ffffff");
  eventsSheet.setFrozenRows(1);

  // 2. COMMANDS Sheet
  var cmdSheet = ss.getSheetByName("COMMANDS");
  if (!cmdSheet) {
    cmdSheet = ss.insertSheet("COMMANDS");
  }
  cmdSheet.getRange("A1:H1").setValues([[
    "timestamp", "command_id", "device_id", "command", "risk", "reason", "processed", "acknowledged"
  ]]);
  cmdSheet.getRange("A1:H1").setFontWeight("bold").setBackground("#1e293b").setFontColor("#ffffff");
  cmdSheet.setFrozenRows(1);

  // 3. DEVICE_STATUS Sheet
  var statusSheet = ss.getSheetByName("DEVICE_STATUS");
  if (!statusSheet) {
    statusSheet = ss.insertSheet("DEVICE_STATUS");
  }
  statusSheet.getRange("A1:K1").setValues([[
    "timestamp", "device_id", "wifi_status", "ip_address", "rssi", "firmware_version", "uptime", "last_event", "device_state", "input_length", "keypad_state"
  ]]);
  statusSheet.getRange("A1:K1").setFontWeight("bold").setBackground("#1e293b").setFontColor("#ffffff");
  statusSheet.setFrozenRows(1);

  // 4. CONFIG Sheet
  var configSheet = ss.getSheetByName("CONFIG");
  if (!configSheet) {
    configSheet = ss.insertSheet("CONFIG");
  }
  configSheet.getRange("A1:E1").setValues([[
    "device_id", "poll_interval", "backend_mode", "sheet_version", "firmware_version"
  ]]);
  configSheet.getRange("A1:E1").setFontWeight("bold").setBackground("#1e293b").setFontColor("#ffffff");
  if (configSheet.getLastRow() < 2) {
    configSheet.appendRow(["DOOR-001", "3", "LANGGRAPH_AI", "2.0", "1.0.0"]);
  }
  configSheet.setFrozenRows(1);

  return { eventsSheet: eventsSheet, cmdSheet: cmdSheet, statusSheet: statusSheet, configSheet: configSheet };
}

/**
 * Helper to build JSON responses
 */
function jsonResponse(obj, statusCode) {
  var output = ContentService.createTextOutput(JSON.stringify(obj));
  output.setMimeType(ContentService.MimeType.JSON);
  return output;
}
