/**
 * Logic and controller for Public / Locked Door Access Dashboard.
 * Dual Input Architecture: Physical ESP8266 Keypad + Virtual Web Keypad.
 * Authoritative Backend Pipeline: Random Forest -> LangGraph -> Adaptive PQC -> SQLite Audit.
 */

let currentPin = "";
let physicalInputLength = 0;
let isProcessing = false;
let autoRelockTimer = null;
let currentResetState = "NORMAL"; // NORMAL | RESET_WAITING_OTP | RESET_NEW_PIN | RESET_CONFIRM_PIN
let tempNewPin = "";
let networkHistoryRefreshRunning = false;
let offlineAssessmentInProgress = false;

const NETWORK_FEATURE_COLUMNS = [
  "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
  "fin_flag_number", "syn_flag_number", "rst_flag_number",
  "psh_flag_number", "ack_flag_number", "ece_flag_number",
  "cwr_flag_number", "ack_count", "syn_count", "fin_count",
  "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH",
  "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv",
  "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
  "IAT", "Number", "Variance",
];

/**
 * Updates the masked PIN display.
 * Renders styled dot glyphs (●) for entered characters and dimmed circles (○) for empty slots.
 * Plaintext PIN is NEVER rendered to DOM or logged in console.
 * Supports dual input: Virtual UI Keypad + Physical ESP8266 Hardware Keypad.
 */
function updatePinDisplay(customLen) {
  const display = document.getElementById("pinDisplay");
  if (!display) return;

  const targetSlots = currentResetState === "RESET_WAITING_OTP" ? 6 : 4;
  // If user is actively typing locally via virtual keypad, prioritize currentPin.length;
  // otherwise reflect physical ESP8266 keypad input length.
  const len = (currentPin.length > 0)
    ? currentPin.length
    : (customLen !== undefined ? customLen : physicalInputLength);
  
  let html = "";
  if (len === 0) {
    for (let i = 0; i < targetSlots; i++) {
      html += '<span class="pin-dot placeholder">○</span>';
    }
  } else {
    for (let i = 0; i < len; i++) {
      html += '<span class="pin-dot">●</span>';
    }
    for (let i = len; i < targetSlots; i++) {
      html += '<span class="pin-dot placeholder">○</span>';
    }
  }

  display.innerHTML = html;
}

/**
 * Appends a digit or matrix letter to the active PIN buffer.
 */
function pressKey(key) {
  if (isProcessing) return;

  const maxLen = currentResetState === "RESET_WAITING_OTP" ? 6 : 8;
  if (currentPin.length < maxLen) {
    currentPin += key;
    updatePinDisplay();
  }

  // Auto-submit when standard 4-digit numeric PIN is entered in normal mode
  if (currentResetState === "NORMAL" && currentPin.length === 4 && /^\d{4}$/.test(currentPin)) {
    submitPin();
  }
}

/**
 * Removes the last entered character from the PIN buffer.
 */
function backspacePin() {
  if (isProcessing) return;
  if (currentPin.length > 0) {
    currentPin = currentPin.slice(0, -1);
    updatePinDisplay();
  }
}

/**
 * Clears the entire PIN buffer without triggering any network request.
 */
function clearPin() {
  if (isProcessing) return;
  currentPin = "";
  physicalInputLength = 0;
  updatePinDisplay();
}

/**
 * Populates and submits a PIN string for quick simulation testing.
 */
function simulatePin(pin) {
  if (isProcessing) return;
  currentPin = String(pin);
  updatePinDisplay();
  submitPin();
}

/**
 * Initiates AABB Password Reset sequence.
 */
async function triggerAabb() {
  try {
    const res = await API.post("/api/reset/request", { source: "WEB_DASHBOARD" });
    showToast(res.message || "Reset mode triggered. Generate OTP in Owner Console.", "info");
    
    currentResetState = "RESET_WAITING_OTP";
    currentPin = "";
    updatePinDisplay();
    updateResetTrackerUI();

    const logBox = document.getElementById("decisionLogBox");
    if (logBox) {
      logBox.innerHTML = `
        <strong style="color:var(--yellow)">AABB PASSWORD RESET TRIGGERED</strong><br>
        ${escapeHtml(res.message)}<br>
        <em>Open <a href="/owner" style="color:var(--cyan)">Owner Security Console</a> to view/generate 6-digit OTP.</em>
      `;
    }
  } catch (err) {
    showToast(err.message || "Failed to trigger reset", "danger");
  }
}

/**
 * Submits the current PIN or reset payload to the existing backend API.
 */
async function submitPin() {
  if (!currentPin || isProcessing) return;

  const pinValue = currentPin;
  clearPin();

  // If user entered AABB, trigger reset flow
  if (pinValue.toUpperCase() === "AABB") {
    await triggerAabb();
    return;
  }

  // Handle Multi-Step Reset Flow via Virtual Keypad
  if (currentResetState === "RESET_WAITING_OTP") {
    await handleVerifyOtp(pinValue);
    return;
  } else if (currentResetState === "RESET_NEW_PIN") {
    tempNewPin = pinValue;
    currentResetState = "RESET_CONFIRM_PIN";
    updateResetTrackerUI();
    showToast("Now re-enter new PIN to confirm", "info");
    return;
  } else if (currentResetState === "RESET_CONFIRM_PIN") {
    await handleSetNewPassword(tempNewPin, pinValue);
    return;
  }

  // Standard Door PIN Authentication
  isProcessing = true;
  setPromptState("AUTHENTICATING...", "prompt-auth");
  
  const pill = document.getElementById("doorStatusPill");
  if (pill) {
    pill.className = "door-status-pill status-auth";
    pill.textContent = "AUTHENTICATING & RUNNING LANGGRAPH PIPELINE...";
  }

  try {
    const data = await API.post("/api/authenticate", { password: pinValue });
    await animatePipelineNodes(data);
    updateAdaptiveSecurityDecision({
      event_id: data.event_id,
      decision_id: data.decision_id,
      source: "WEB_UI",
      result: data.authenticated ? "SUCCESS" : "FAILED",
      device_risk: data.ml_risk_level || data.risk_level,
      network_risk: data.network_risk_level || "UNKNOWN",
      final_risk: data.agent_risk_level || data.risk_level,
      action: data.action?.type || data.action?.action || "ASSESSMENT COMPLETE",
    }, data.security_profile);

    // Update Telemetry Stats Bar
    const riskLevel = data.risk_level || "LOW";
    const statRisk = document.getElementById("statRiskLevel");
    if (statRisk) {
      statRisk.textContent = riskLevel;
      statRisk.style.color = riskLevel === "HIGH" ? "var(--red)" : (riskLevel === "MEDIUM" ? "var(--yellow)" : "var(--green)");
    }

    const statFailed = document.getElementById("statFailedAttempts");
    if (statFailed) {
      statFailed.textContent = data.failed_attempts ?? 0;
    }
    
    const prof = data.security_profile || {};
    const kemName = prof.kem || "ML-KEM-512";
    const sigName = prof.signature || "ML-DSA-44";

    const statPqc = document.getElementById("statPqcName");
    if (statPqc) statPqc.textContent = kemName;

    const pqcBadge = document.getElementById("pqcBadge");
    if (pqcBadge) pqcBadge.textContent = `🔐 ${kemName} / ${sigName}`;

    // Update Column 3 Telemetry
    const kemVal = document.getElementById("pqcKemVal");
    if (kemVal) kemVal.textContent = kemName;
    const sigVal = document.getElementById("pqcSigVal");
    if (sigVal) sigVal.textContent = sigName;
    const lvlVal = document.getElementById("pqcLevelVal");
    if (lvlVal) {
      lvlVal.textContent = riskLevel === "HIGH" ? "Level 5 (AES-256 Eq.)" : (riskLevel === "MEDIUM" ? "Level 3 (AES-192 Eq.)" : "Level 1 (AES-128 Eq.)");
    }

    // Update Door Visualizer
    updateDoorVisuals(data.door_state, data.user);

    // Render LangGraph Reasoning & Security Decisions
    renderDecisionLog(data, prof);

    if (data.authenticated) {
      showToast(`Access Authorized: Welcome ${data.user}!`, "success");
      setPromptState("ACCESS GRANTED", "prompt-normal");
      
      // Auto-relock simulated door after 5 seconds
      if (autoRelockTimer) clearTimeout(autoRelockTimer);
      autoRelockTimer = setTimeout(async () => {
        await API.post("/api/door/lock");
        updateDoorVisuals("LOCKED");
        setPromptState("ENTER PIN", "prompt-normal");
      }, 5000);
    } else {
      if (data.door_state === "LOCKOUT" || data.lockout_active || riskLevel === "HIGH") {
        showToast("Intrusion risk detected: Security lockout engaged!", "danger");
        setPromptState("SECURITY LOCKOUT", "prompt-lockout");
        setKeypadDisabled(true);
      } else {
        showToast("Access Denied: Incorrect credentials.", "warn");
        setPromptState("ACCESS DENIED — RETRY", "prompt-lockout");
        setTimeout(() => setPromptState("ENTER PIN", "prompt-normal"), 2500);
      }
    }
  } catch (err) {
    showToast(err.message || "Authentication error", "danger");
    updateDoorVisuals("LOCKED");
    setPromptState("ERROR — RETRY", "prompt-lockout");
    setTimeout(() => setPromptState("ENTER PIN", "prompt-normal"), 2500);
  } finally {
    isProcessing = false;
  }
}

/**
 * Handles OTP verification in reset flow.
 */
async function handleVerifyOtp(otpValue) {
  isProcessing = true;
  setPromptState("VERIFYING OTP...", "prompt-auth");
  try {
    const res = await API.post("/api/reset/verify-otp", { otp: otpValue });
    if (res.success) {
      showToast("OTP Verified! Enter new 4-digit PIN.", "success");
      currentResetState = "RESET_NEW_PIN";
      updateResetTrackerUI();
    } else {
      showToast(res.error || "Invalid OTP", "danger");
      setPromptState("INVALID OTP — RETRY", "prompt-lockout");
    }
  } catch (e) {
    showToast(e.message || "OTP verification failed", "danger");
    setPromptState("INVALID OTP — RETRY", "prompt-lockout");
  } finally {
    isProcessing = false;
  }
}

/**
 * Handles committing new password in reset flow.
 */
async function handleSetNewPassword(newPin, confirmPin) {
  if (newPin !== confirmPin) {
    showToast("PIN mismatch! Restarting reset entry.", "warn");
    currentResetState = "RESET_NEW_PIN";
    tempNewPin = "";
    updateResetTrackerUI();
    return;
  }

  isProcessing = true;
  setPromptState("UPDATING PIN...", "prompt-auth");
  try {
    const hashPin = async (value) => {
      const bytes = new TextEncoder().encode(value);
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    };
    const res = await API.post("/api/reset/set-password", {
      new_pin_hash: await hashPin(newPin),
      confirm_pin_hash: await hashPin(confirmPin),
    });
    if (res.success) {
      showToast("Password updated successfully! Enter new PIN to unlock.", "success");
      currentResetState = "NORMAL";
      tempNewPin = "";
      updateResetTrackerUI();
      updateDoorVisuals("LOCKED");
    } else {
      showToast(res.error || "Failed to update PIN", "danger");
      currentResetState = "NORMAL";
      updateResetTrackerUI();
    }
  } catch (e) {
    showToast(e.message || "Failed to update password", "danger");
    currentResetState = "NORMAL";
    updateResetTrackerUI();
  } finally {
    isProcessing = false;
  }
}

/**
 * Updates the prompt pill text and CSS class.
 */
function setPromptState(text, className) {
  const prompt = document.getElementById("terminalPrompt");
  if (!prompt) return;
  prompt.textContent = text;
  prompt.className = `terminal-prompt-pill ${className || ''}`;
}

/**
 * Enables or disables virtual keypad interactive buttons.
 */
function setKeypadDisabled(disabled) {
  const keys = document.querySelectorAll(".key-btn, .toolbar-btn");
  keys.forEach((k) => {
    k.disabled = disabled;
  });
}

/**
 * Updates UI indicators for Multi-Step Password Reset tracker.
 */
function updateResetTrackerUI() {
  const badge = document.getElementById("trackerBadge");
  const stepNormal = document.getElementById("step-normal");
  const stepAabb = document.getElementById("step-aabb");
  const stepOtp = document.getElementById("step-otp");

  if (stepNormal) stepNormal.className = "tracker-step";
  if (stepAabb) stepAabb.className = "tracker-step";
  if (stepOtp) stepOtp.className = "tracker-step";

  if (currentResetState === "RESET_WAITING_OTP") {
    if (badge) { badge.textContent = "WAITING OTP"; badge.style.color = "var(--yellow)"; }
    if (stepAabb) stepAabb.classList.add("active");
    setPromptState("AABB: ENTER 6-DIGIT OTP", "prompt-reset");
  } else if (currentResetState === "RESET_NEW_PIN") {
    if (badge) { badge.textContent = "NEW PIN"; badge.style.color = "var(--purple)"; }
    if (stepOtp) stepOtp.classList.add("active");
    setPromptState("ENTER NEW 4-DIGIT PIN", "prompt-reset");
  } else if (currentResetState === "RESET_CONFIRM_PIN") {
    if (badge) { badge.textContent = "CONFIRM PIN"; badge.style.color = "var(--purple)"; }
    if (stepOtp) stepOtp.classList.add("active");
    setPromptState("CONFIRM NEW 4-DIGIT PIN", "prompt-reset");
  } else {
    if (badge) { badge.textContent = "NORMAL"; badge.style.color = "var(--green)"; }
    if (stepNormal) stepNormal.classList.add("active");
    setPromptState("ENTER PIN", "prompt-normal");
  }
}

/**
 * Renders LangGraph agent decision log and recommendations.
 */
function renderDecisionLog(data, prof) {
  const logBox = document.getElementById("decisionLogBox");
  if (!logBox) return;

  const reasons = (data.reasoning || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  const recs = (data.recommendations || []).map((rc) => `<li>${escapeHtml(rc)}</li>`).join("");

  logBox.innerHTML = `
    <div style="display:flex; justify-content:space-between; margin-bottom:8px; flex-wrap:wrap; gap:8px">
      <strong>Result: <span style="color:${data.authenticated ? 'var(--green)' : 'var(--red)'}">${data.authenticated ? 'AUTHORIZED' : 'ACCESS DENIED'}</span></strong>
      <span>Risk: <b style="color:${data.risk_level === 'HIGH' ? 'var(--red)' : (data.risk_level === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)')}">${data.risk_level || 'LOW'}</b> • PQC: <b>${escapeHtml(prof.kem || 'ML-KEM-512')}</b></span>
    </div>
    <div style="font-size:12px; color:var(--text); margin-bottom:4px"><b>Agent Reasoning:</b></div>
    <ul style="padding-left:18px; color:var(--muted); margin-bottom:8px">${reasons || '<li>Standard security evaluation complete.</li>'}</ul>
    ${recs ? `<div style="font-size:12px; color:var(--text); margin-bottom:4px"><b>Advisories:</b></div><ul style="padding-left:18px; color:var(--muted)">${recs}</ul>` : ''}
  `;
}

/**
 * Physical Keyboard Event Listener (Supports 0-9, A-D, Enter, Backspace, Escape, *)
 */
document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  
  if ((e.key >= "0" && e.key <= "9") || ["a", "b", "c", "d", "A", "B", "C", "D"].includes(e.key)) {
    pressKey(e.key.toUpperCase());
    e.preventDefault();
  } else if (e.key === "Enter" || e.key === "#") {
    submitPin();
    e.preventDefault();
  } else if (e.key === "Backspace") {
    backspacePin();
    e.preventDefault();
  } else if (e.key === "Escape" || e.key === "*") {
    clearPin();
    e.preventDefault();
  }
});

/**
 * Sequentially animate LangGraph pipeline nodes during authentication.
 */
async function animatePipelineNodes(result) {
  const nodes = ["observe", "assess", "reassess", "plan", "decide", "act", "recommend", "reflect"];
  for (const n of nodes) {
    const el = document.getElementById(`node-${n}`);
    if (el) el.classList.add("active");
    await new Promise((r) => setTimeout(r, 85));
  }
  setTimeout(() => {
    nodes.forEach((n) => {
      const el = document.getElementById(`node-${n}`);
      if (el) el.classList.remove("active");
    });
  }, 1200);
}

/**
 * Updates 3D Simulated Door Visuals.
 */
function updateDoorVisuals(doorState, userLabel = "SECURE") {
  const leaf = document.getElementById("doorLeaf");
  const pill = document.getElementById("doorStatusPill");
  const icon = document.getElementById("doorIcon");
  const label = document.getElementById("doorUserLabel");
  const bolt = document.getElementById("lockBolt");
  const statDoor = document.getElementById("statDoorState");

  if (statDoor) statDoor.textContent = doorState;

  if (doorState === "OPEN") {
    if (leaf) leaf.classList.add("open");
    if (pill) {
      pill.className = "door-status-pill status-open";
      pill.textContent = `DOOR UNLOCKED • AUTHORIZED (${userLabel})`;
    }
    if (icon) icon.textContent = "🔓";
    if (label) label.textContent = userLabel;
    if (bolt) bolt.style.background = "var(--green)";
    if (statDoor) statDoor.style.color = "var(--green)";
  } else if (doorState === "LOCKOUT") {
    if (leaf) leaf.classList.remove("open");
    if (pill) {
      pill.className = "door-status-pill status-lockout";
      pill.textContent = "⚠️ SECURITY LOCKOUT ACTIVE";
    }
    if (icon) icon.textContent = "🚨";
    if (label) label.textContent = "INTRUSION LOCK";
    if (bolt) bolt.style.background = "var(--red)";
    if (statDoor) statDoor.style.color = "var(--red)";
  } else {
    if (leaf) leaf.classList.remove("open");
    if (pill) {
      pill.className = "door-status-pill status-locked";
      pill.textContent = "DOOR LOCKED";
    }
    if (icon) icon.textContent = "🔒";
    if (label) label.textContent = "SECURE";
    if (bolt) bolt.style.background = "var(--red)";
    if (statDoor) statDoor.style.color = "var(--red)";
  }
}

function updateAdaptiveSecurityDecision(decision, profile = {}) {
  const deviceRisk = decision?.device_risk || "UNKNOWN";
  const networkRisk = decision?.network_risk || "UNKNOWN";
  const finalRisk = decision?.final_risk || "UNKNOWN";
  const setText = (id, value) => {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  };

  setText("monitorDeviceRisk", deviceRisk);
  setText("monitorNetworkRisk", networkRisk);
  setText("monitorFinalRisk", finalRisk);
  setText("monitorPqcProfile", profile.kem || "ML-KEM-512");
  setText("adaptiveMonitorStatus", "ASSESSMENT COMPLETE");

  const networkEvidence = networkRisk === "UNKNOWN"
    ? "NO MATCHING NETWORK OBSERVATION"
    : `Network evidence risk: ${networkRisk}`;
  const when = decision.timestamp ? ` • ${formatTimestamp(decision.timestamp)}` : "";
  const ids = [
    decision.event_id ? `Event ${decision.event_id}` : "",
    decision.decision_id ? `Decision ${decision.decision_id}` : "",
  ].filter(Boolean).join(" / ");
  setText(
    "monitorEvidenceStatus",
    `${decision.source || "AUTHENTICATION"} / ${decision.result || "ASSESSED"}${when}${ids ? ` • ${ids}` : ""} • ${networkEvidence} • Network model inference unavailable for live packet metadata.`
  );
}

function updateDoorCaptureStatus(capture) {
  const statusElement = document.getElementById("doorCaptureStatus");
  const badge = document.getElementById("adaptiveMonitorStatus");
  const select = document.getElementById("doorCaptureInterface");
  const startButton = document.getElementById("doorCaptureStart");
  const stopButton = document.getElementById("doorCaptureStop");
  if (!statusElement || !badge || !select || !startButton || !stopButton) return;

  const status = capture.status || "ERROR";
  const running = status === "STARTING" || status === "RUNNING";
  badge.textContent = running ? "MONITORING" : status === "ERROR" || capture.capability_error
    ? "NETWORK EVIDENCE UNAVAILABLE"
    : "MONITORING";
  startButton.disabled = running || !capture.interfaces?.length;
  stopButton.disabled = !running;
  select.disabled = running;

  const interfaces = capture.interfaces || [];
  if (!running && select.dataset.interfaceList !== JSON.stringify(interfaces)) {
    select.replaceChildren(new Option("Select an authorized interface", ""));
    interfaces.forEach((item) => {
      select.add(new Option(`${item.description} (${item.name})`, item.name));
    });
    select.dataset.interfaceList = JSON.stringify(interfaces);
  }
  if (capture.interface) select.value = capture.interface;

  const details = [
    capture.capability_error || capture.error
      ? `CAPTURE UNAVAILABLE: ${capture.capability_error || capture.error}`
      : `Capture ${status.toLowerCase()}${capture.interface ? ` on ${capture.interface}` : ""}.`,
    `Packets observed: ${capture.packet_count ?? 0}.`,
    `Network model: unavailable; captured proxies are not training-compatible.`,
    "Capture is passive and assessment-only; no door commands are issued.",
  ];
  statusElement.textContent = details.join(" ");
}

async function refreshDoorNetworkAssessmentHistory() {
  if (networkHistoryRefreshRunning) return;
  networkHistoryRefreshRunning = true;

  const tbody = document.getElementById("doorNetworkAssessmentsBody");
  const status = document.getElementById("doorNetworkHistoryStatus");
  try {
    const assessments = await API.get("/api/network/assessments?limit=10");
    if (!Array.isArray(assessments)) {
      throw new Error("Network assessment API response was not a list.");
    }
    if (!assessments.length) {
      status.textContent = "No persisted network assessments are available. Authentication events are not network observations.";
      tbody.innerHTML = '<tr><td colspan="7">No network assessments recorded.</td></tr>';
      return;
    }

    tbody.innerHTML = assessments.map((assessment) => {
      const prediction = assessment.network_prediction || {};
      const source = assessment.assessment_source || prediction.assessment_type || prediction.telemetry_source || "UNKNOWN";
      const live = source === "LIVE_PACKET_CAPTURE_PROTOTYPE";
      const networkLabel = live
        ? `${prediction.network_evidence_status || "LIVE CAPTURE PROTOTYPE"} / ${assessment.network_risk || "UNKNOWN"} / ${prediction.predicted_attack || prediction.model_inference_status || "MODEL INFERENCE UNAVAILABLE"}`
        : `OFFLINE/SUPPLIED CSV TEST DATA / ${assessment.network_risk || "UNKNOWN"} / ${prediction.predicted_attack || "—"}`;
      const confidenceValue = prediction.max_confidence ?? assessment.network_confidence?.max_confidence;
      const confidence = confidenceValue == null
        ? "—"
        : `${(Number(confidenceValue) * 100).toFixed(1)}%`;
      const risk = (assessment.final_risk || "UNKNOWN").toUpperCase();
      const riskClass = risk === "HIGH" ? "tag-high" : risk === "MEDIUM" ? "tag-med" : risk === "LOW" ? "tag-low" : "tag-web";
      const pqc = [assessment.pqc_kem, assessment.pqc_sig].filter(Boolean).join(" + ") || "—";
      return `<tr>
        <td>${escapeHtml(formatTimestamp(assessment.timestamp))}</td>
        <td>${escapeHtml(assessment.device_risk || "UNKNOWN")}</td>
        <td>${escapeHtml(networkLabel)}</td>
        <td>${escapeHtml(confidence)}</td>
        <td><span class="badge-tag ${riskClass}">${escapeHtml(risk)}</span></td>
        <td>${escapeHtml(pqc)}</td>
        <td>${escapeHtml(assessment.execution_status || "—")}</td>
      </tr>`;
    }).join("");

    const latest = assessments[0];
    const latestSource = latest.assessment_source || latest.network_prediction?.telemetry_source || "UNKNOWN";
    status.textContent = `${assessments.length} persisted network assessment${assessments.length === 1 ? "" : "s"} shown, latest ${formatTimestamp(latest.timestamp)}. ${latestSource === "LIVE_PACKET_CAPTURE_PROTOTYPE" ? "Live capture prototype records are distinct from model inference." : "Offline/supplied CSV results are historical test evidence, not live traffic."} Authentication/device events are displayed separately above.`;
  } catch (error) {
    console.error("Unable to load protected network assessment history:", error);
    status.textContent = `Network assessment history is unavailable: ${error.message || "Unable to load persisted records."}`;
    tbody.innerHTML = '<tr><td colspan="7">Unable to load network assessment history. Retry will occur automatically.</td></tr>';
  } finally {
    networkHistoryRefreshRunning = false;
  }
}

async function readNetworkCsvFeatures(file, dataRowNumber) {
  if (!Number.isSafeInteger(dataRowNumber) || dataRowNumber < 1) {
    throw new Error("Data row number must be a positive whole number, excluding the header.");
  }

  const reader = file.stream().getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let lineNumber = 0;
  let headersValidated = false;

  const parseLine = (line) => {
    const fields = line.replace(/\r$/, "").split(",");
    if (!headersValidated) {
      if (fields[0]) fields[0] = fields[0].replace(/^\uFEFF/, "");
      if (
        fields.length !== NETWORK_FEATURE_COLUMNS.length ||
        fields.some((name, index) => name !== NETWORK_FEATURE_COLUMNS[index])
      ) {
        throw new Error("CSV columns must match the 39 CICIoT network feature names and order.");
      }
      headersValidated = true;
      return null;
    }

    lineNumber += 1;
    if (lineNumber !== dataRowNumber) return null;
    if (fields.length !== NETWORK_FEATURE_COLUMNS.length) {
      throw new Error(`CSV data row ${dataRowNumber} must contain exactly 39 feature values.`);
    }

    const features = {};
    for (let index = 0; index < NETWORK_FEATURE_COLUMNS.length; index += 1) {
      const rawValue = fields[index].trim();
      const value = Number(rawValue);
      if (!rawValue || !Number.isFinite(value)) {
        throw new Error(`CSV row ${dataRowNumber} has an invalid numeric value for "${NETWORK_FEATURE_COLUMNS[index]}".`);
      }
      features[NETWORK_FEATURE_COLUMNS[index]] = value;
    }
    return features;
  };

  try {
    while (true) {
      const { done, value } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      let newlineIndex = buffer.indexOf("\n");
      while (newlineIndex >= 0) {
        const features = parseLine(buffer.slice(0, newlineIndex));
        buffer = buffer.slice(newlineIndex + 1);
        if (features) {
          await reader.cancel();
          return features;
        }
        newlineIndex = buffer.indexOf("\n");
      }
      if (done) break;
    }

    if (buffer) {
      const features = parseLine(buffer);
      if (features) return features;
    }
  } finally {
    reader.releaseLock();
  }

  throw new Error(`CSV does not contain data row ${dataRowNumber}. Choose a row within the file's data range.`);
}

function renderOfflineAssessmentResult(result) {
  const container = document.getElementById("doorOfflineCsvResult");
  const prediction = result.network_prediction || {};
  const profile = result.security_profile || {};
  const deviceRisk = result.device_risk || "UNKNOWN";
  const deviceConfidence = Object.entries(result.device_confidence || {})
    .find(([risk]) => risk.toUpperCase() === deviceRisk.toUpperCase())?.[1];
  const confidence = prediction.max_confidence == null
    ? "Unavailable"
    : `${(Number(prediction.max_confidence) * 100).toFixed(1)}% (${prediction.predicted_attack || "unknown attack"})`;
  const action = result.action?.action || result.action?.type || "No action recommended";
  const fields = [
    ["Device risk", `${deviceRisk}${deviceConfidence == null ? "" : ` (${(Number(deviceConfidence) * 100).toFixed(1)}% confidence)`}`],
    ["Network risk / attack", `${result.network_risk || "UNKNOWN"} / ${prediction.predicted_attack || "unknown"}`],
    ["Network confidence", confidence],
    ["Final risk", result.final_risk || "UNKNOWN"],
    ["Selected PQC profile", [profile.kem, profile.signature].filter(Boolean).join(" + ") || "Unavailable"],
    ["Action status", `${result.action_execution_status || "Unavailable"}; recommendation: ${action} (not executed)`],
  ];
  container.innerHTML = `
    <h3>Offline/supplied CSV assessment result</h3>
    <div class="offline-csv-result-grid">${fields.map(([label, value]) =>
      `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`
    ).join("")}</div>
    <p class="network-history-status">Decision ${escapeHtml(result.decision_id || "unavailable")} · ${escapeHtml(formatTimestamp(result.timestamp))} · Assessment-only: no door or hardware action was executed.</p>
  `;
  container.hidden = false;
}

async function analyzeDoorOfflineCsvRow(event) {
  event.preventDefault();
  if (offlineAssessmentInProgress) return;

  const fileInput = document.getElementById("doorNetworkCsvFile");
  const rowInput = document.getElementById("doorNetworkCsvRow");
  const button = document.getElementById("doorNetworkAnalyzeButton");
  const status = document.getElementById("doorOfflineCsvStatus");
  const file = fileInput.files?.[0];
  const rowNumber = Number(rowInput.value);

  if (!file) {
    status.textContent = "Choose a CICIoT CSV file before submitting.";
    return;
  }
  if (!file.name.toLowerCase().endsWith(".csv")) {
    status.textContent = "Choose a .csv dataset file.";
    return;
  }

  offlineAssessmentInProgress = true;
  button.disabled = true;
  status.textContent = `Validating offline/supplied CSV row ${rowNumber} against the CICIoT feature schema...`;
  try {
    const networkFeatures = await readNetworkCsvFeatures(file, rowNumber);
    status.textContent = "Running assessment-only network model and agent analysis; no door action will be executed...";
    const result = await API.post("/api/network/assess-offline", {
      network_features: networkFeatures,
    });
    renderOfflineAssessmentResult(result);
    status.textContent = `Offline/supplied CSV assessment saved with decision ${result.decision_id}. Refreshing persisted history...`;
    await refreshDoorNetworkAssessmentHistory();
    status.textContent = `Assessment saved and shown at the top of history. Offline/supplied data only; no door or hardware action was executed.`;
  } catch (error) {
    status.textContent = error.message || "Unable to analyze the selected offline CSV row.";
    showToast(status.textContent, "danger");
  } finally {
    offlineAssessmentInProgress = false;
    button.disabled = false;
  }
}

async function refreshDoorCapture() {
  const controls = document.getElementById("doorCaptureControls");
  const status = document.getElementById("doorCaptureStatus");
  try {
    const owner = await API.get("/api/owner/status");
    if (!owner.authenticated) {
      controls.hidden = true;
      status.textContent = "Capture controls require an authenticated owner. No capture is started automatically.";
      return;
    }

    controls.hidden = false;
    updateDoorCaptureStatus(await API.get("/api/owner/network-capture"));
  } catch (error) {
    if (controls) controls.hidden = true;
    if (status) status.textContent = `Capture status unavailable: ${error.message || "Owner session or capture service unavailable."}`;
  }
}

async function startDoorCapture() {
  const interfaceName = document.getElementById("doorCaptureInterface").value;
  const duration = Number(document.getElementById("doorCaptureDuration").value);
  if (!interfaceName) {
    showToast("Select an authorized network interface first.", "warn");
    return;
  }
  if (!Number.isInteger(duration) || duration < 10 || duration > 300) {
    showToast("Capture duration must be between 10 and 300 seconds.", "warn");
    return;
  }

  try {
    const capture = await API.post("/api/owner/network-capture/start", {
      interface: interfaceName,
      duration_seconds: duration,
    });
    updateDoorCaptureStatus(capture);
  } catch (error) {
    showToast(error.message || "Unable to start passive capture.", "danger");
    await refreshDoorCapture();
  }
}

async function stopDoorCapture() {
  try {
    updateDoorCaptureStatus(await API.post("/api/owner/network-capture/stop"));
  } catch (error) {
    showToast(error.message || "Unable to stop passive capture.", "danger");
    await refreshDoorCapture();
  }
}

/**
 * Manual Lock Action.
 */
async function manualLockDoor() {
  try {
    await API.post("/api/door/lock");
    updateDoorVisuals("LOCKED");
    showToast("Door manually locked.", "info");
  } catch (e) {
    showToast(e.message || "Failed to lock door", "danger");
  }
}

/**
 * Manual Force Unlock Action.
 */
async function manualUnlockDoor() {
  try {
    await API.post("/api/door/unlock");
    updateDoorVisuals("OPEN", "MANUAL");
    showToast("Door manually unlocked.", "info");
  } catch (e) {
    showToast(e.message || "Failed to unlock door", "danger");
  }
}

/**
 * Periodic Telemetry Polling (Door status, ESP8266 node status, and Reset status).
 */
async function pollStatus() {
  try {
    const [doorRes, hwRes, resetRes] = await Promise.all([
      API.get("/api/door/status"),
      API.get("/api/device/status"),
      API.get("/api/reset/status"),
    ]);
    if (doorRes.latest_security_decision) {
      updateAdaptiveSecurityDecision(doorRes.latest_security_decision, doorRes.pqc_profile || {});
    }

    // Handle Lockout state from backend
    if (doorRes.lockout_active) {
      setKeypadDisabled(true);
      setPromptState(`SECURITY LOCKOUT (${doorRes.lockout_remaining_seconds || 0}s)`, "prompt-lockout");
      updateDoorVisuals("LOCKOUT");
    } else {
      if (!isProcessing) {
        setKeypadDisabled(false);
        if (currentResetState === "NORMAL") {
          setPromptState("ENTER PIN", "prompt-normal");
        }
      }
    }

    // Update Door & Telemetry Bar
    if (!isProcessing) {
      updateDoorVisuals(doorRes.door_state);
      
      const statRisk = document.getElementById("statRiskLevel");
      if (statRisk) {
        statRisk.textContent = doorRes.risk_level;
        statRisk.style.color = doorRes.risk_level === "HIGH" ? "var(--red)" : (doorRes.risk_level === "MEDIUM" ? "var(--yellow)" : "var(--green)");
      }

      const statFailed = document.getElementById("statFailedAttempts");
      if (statFailed) statFailed.textContent = doorRes.failed_attempts;
      
      const p = doorRes.pqc_profile || {};
      const statPqc = document.getElementById("statPqcName");
      if (statPqc) statPqc.textContent = p.kem || "ML-KEM-512";
      
      const pqcBadge = document.getElementById("pqcBadge");
      if (pqcBadge) pqcBadge.textContent = `🔐 ${p.kem || 'ML-KEM-512'} / ${p.signature || 'ML-DSA-44'}`;

      const kemVal = document.getElementById("pqcKemVal");
      if (kemVal) kemVal.textContent = p.kem || "ML-KEM-512";
      const sigVal = document.getElementById("pqcSigVal");
      if (sigVal) sigVal.textContent = p.signature || "ML-DSA-44";
    }

    // Sync Reset Mode state if active
    if (resetRes && resetRes.active_session) {
      if (currentResetState === "NORMAL") {
        currentResetState = resetRes.status === "OTP_VERIFIED" ? "RESET_NEW_PIN" : "RESET_WAITING_OTP";
        updateResetTrackerUI();
      }
    } else if (currentResetState === "RESET_WAITING_OTP") {
      currentResetState = "NORMAL";
      updateResetTrackerUI();
    }

    // Synchronize physical ESP8266 keypad masked input length if virtual keypad is not actively being used
    if (hwRes && typeof hwRes.input_length === "number") {
      const hwLen = Math.max(0, hwRes.input_length);
      if (currentPin.length === 0 && !isProcessing) {
        if (physicalInputLength !== hwLen) {
          physicalInputLength = hwLen;
          updatePinDisplay();
        }
      }
    }

    // Update ESP8266 Badge
    const hwBadge = document.getElementById("hwBadge");
    if (hwBadge) {
      const isHwOnline = hwRes.is_online || hwRes.wifi_status === "CONNECTED";
      hwBadge.className = `badge ${isHwOnline ? 'badge-online' : 'badge-offline'}`;
      hwBadge.innerHTML = `<span class="dot">●</span> ESP8266: ${isHwOnline ? 'ONLINE (' + (hwRes.ip_address || 'WiFi') + ')' : 'OFFLINE'}`;
    }
  } catch (e) {
    // Silent catch for network jitter
  }
}

// Initial initialization
updatePinDisplay();
updateResetTrackerUI();
pollStatus();
refreshDoorCapture();
refreshDoorNetworkAssessmentHistory();
document.getElementById("doorOfflineCsvForm").addEventListener("submit", analyzeDoorOfflineCsvRow);
setInterval(pollStatus, 1000);
setInterval(refreshDoorCapture, 5000);
setInterval(refreshDoorNetworkAssessmentHistory, 5000);
