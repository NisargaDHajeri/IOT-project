/**
 * Controller and state manager for Owner Security Operations Console.
 */

let otpCountdownTimer = null;
let currentOtpSecondsRemaining = 0;

async function checkOwnerAuth() {
  try {
    const res = await API.get("/api/owner/status");
    if (res.authenticated) {
      document.getElementById("authBarrier").style.display = "none";
      document.getElementById("ownerConsoleShell").style.display = "block";
      document.getElementById("ownerUserBadge").textContent = `Admin: ${res.username}`;
      loadOwnerData();
      startPolling();
    } else {
      document.getElementById("authBarrier").style.display = "flex";
      document.getElementById("ownerConsoleShell").style.display = "none";
    }
  } catch (err) {
    document.getElementById("authBarrier").style.display = "flex";
  }
}

async function handleOwnerLogin(e) {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value.trim();
  const btn = document.getElementById("loginBtn");

  btn.disabled = true;
  btn.textContent = "AUTHENTICATING...";

  try {
    const res = await API.post("/api/owner/login", { username, password });
    showToast("Owner authenticated successfully!", "success");
    checkOwnerAuth();
  } catch (err) {
    showToast(err.message || "Invalid owner credentials", "danger");
  } finally {
    btn.disabled = false;
    btn.textContent = "AUTHENTICATE OWNER";
  }
}

async function handleOwnerLogout() {
  try {
    await API.post("/api/owner/logout");
    showToast("Logged out of Owner Console", "info");
    checkOwnerAuth();
  } catch (err) {
    window.location.reload();
  }
}

async function overrideLockDoor() {
  try {
    await API.post("/api/door/lock");
    showToast("Simulated door locked manually by Owner", "info");
    loadOwnerData();
  } catch (err) {
    showToast(err.message || "Lock failed", "danger");
  }
}

async function overrideUnlockDoor() {
  try {
    await API.post("/api/door/unlock");
    showToast("Simulated door unlocked manually by Owner", "success");
    loadOwnerData();
  } catch (err) {
    showToast(err.message || "Unlock failed", "danger");
  }
}

// OTP Management & Live Countdown
async function generateResetOtp() {
  try {
    const res = await API.post("/api/reset/generate-otp");
    showToast("6-Digit Reset OTP Generated!", "success");
    displayActiveOtp(res.otp, res.expires_in_seconds || 120);
  } catch (err) {
    showToast(err.message || "Failed to generate OTP", "danger");
  }
}

async function revokeActiveOtp() {
  try {
    await API.post("/api/reset/revoke");
    showToast("Reset session and OTP revoked", "info");
    clearOtpDisplay();
  } catch (err) {
    showToast(err.message || "Revoke failed", "danger");
  }
}

function displayActiveOtp(otp, seconds) {
  const codeBox = document.getElementById("otpCodeDisplay");
  const timerBox = document.getElementById("otpCountdownDisplay");
  const revokeBtn = document.getElementById("revokeOtpBtn");

  codeBox.textContent = `${otp.slice(0,3)} ${otp.slice(3)}`;
  codeBox.style.color = "var(--cyan)";
  revokeBtn.style.display = "inline-block";

  currentOtpSecondsRemaining = seconds;
  if (otpCountdownTimer) clearInterval(otpCountdownTimer);

  function updateClock() {
    if (currentOtpSecondsRemaining <= 0) {
      clearInterval(otpCountdownTimer);
      clearOtpDisplay("EXPIRED");
      return;
    }
    const mins = Math.floor(currentOtpSecondsRemaining / 60);
    const secs = currentOtpSecondsRemaining % 60;
    timerBox.textContent = `Expires in ${String(mins).padStart(2,"0")}:${String(secs).padStart(2,"0")}`;
    currentOtpSecondsRemaining--;
  }

  updateClock();
  otpCountdownTimer = setInterval(updateClock, 1000);
}

function clearOtpDisplay(stateText = "NO ACTIVE OTP") {
  if (otpCountdownTimer) clearInterval(otpCountdownTimer);
  document.getElementById("otpCodeDisplay").textContent = stateText;
  document.getElementById("otpCodeDisplay").style.color = "var(--muted)";
  document.getElementById("otpCountdownDisplay").textContent = "Click above to generate 2-minute OTP";
  document.getElementById("revokeOtpBtn").style.display = "none";
}

async function commitDirectPasswordReset() {
  const newPin = document.getElementById("newPinInput").value.trim();
  const confirmPin = document.getElementById("confirmPinInput").value.trim();

  if (!newPin || !confirmPin) {
    showToast("Please enter and confirm the new PIN", "warn");
    return;
  }
  if (newPin !== confirmPin) {
    showToast("Passwords do not match", "danger");
    return;
  }

  try {
    // Generate an internal OTP verification or direct update
    const otpRes = await API.post("/api/reset/generate-otp");
    await API.post("/api/reset/verify-otp", { otp: otpRes.otp });
    const resetRes = await API.post("/api/reset/set-password", { new_password: newPin, confirm_password: confirmPin });
    showToast(resetRes.message || "Password updated successfully!", "success");
    document.getElementById("newPinInput").value = "";
    document.getElementById("confirmPinInput").value = "";
    clearOtpDisplay();
    loadOwnerData();
  } catch (err) {
    showToast(err.message || "Password reset failed", "danger");
  }
}

function renderOwnerEventsTable(result) {
  const tbody = document.getElementById("eventsTableBody");
  try {
    if (result.status !== "fulfilled") throw result.reason;
    const events = result.value?.events;
    if (!Array.isArray(events)) throw new Error("Events API response did not contain an events array.");
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--muted)">No security access events logged yet.</td></tr>';
      return;
    }
    tbody.innerHTML = events.map((event) => {
      const success = event.result === "SUCCESS";
      const risk = (event.agent_risk || "LOW").toLowerCase();
      const riskTag = risk === "high" ? "tag-high" : (risk === "medium" ? "tag-med" : "tag-low");
      const sourceTag = event.source === "ESP8266_KEYPAD" ? "tag-hw" : "tag-web";
      return `<tr>
        <td>${formatTimestamp(event.timestamp)}</td>
        <td><span class="badge-tag ${sourceTag}">${escapeHtml(event.source)}</span><br><small>Event: ${escapeHtml(event.event_id || "—")}<br>Decision: ${escapeHtml(event.decision_id || "—")}</small></td>
        <td style="font-family:monospace;color:#aeb8ff">${escapeHtml(event.attempted_hash || '••••')}</td>
        <td><b>${escapeHtml(event.user)}</b></td>
        <td><span style="color:${success ? 'var(--green)' : 'var(--red)'};font-weight:800">${escapeHtml(event.result)}</span></td>
        <td><span class="badge-tag ${riskTag}">${escapeHtml(event.ml_risk || 'LOW')}</span></td>
        <td><span class="badge-tag ${riskTag}">${escapeHtml(event.agent_risk || event.final_risk || 'LOW')}</span></td>
        <td style="font-family:monospace;font-size:11px;color:var(--cyan)">${escapeHtml(event.pqc_kem || 'ML-KEM-512')}</td>
        <td>${escapeHtml(event.action_taken || 'RECORD')}</td>
      </tr>`;
    }).join("");
  } catch (error) {
    console.error("Unable to load persisted owner security events:", error);
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--red)">Unable to load security events: ${escapeHtml(error?.message || "Unknown API error")}</td></tr>`;
  } finally {
    if (tbody.textContent.includes("Loading immutable security audit trail")) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--red)">Security events did not finish loading. Refresh to retry.</td></tr>';
    }
  }
}

function renderRecentSecurityDecisions(result) {
  const tbody = document.getElementById("recentSecurityDecisionsBody");
  try {
    if (result.status !== "fulfilled") throw result.reason;
    const events = result.value?.events;
    if (!Array.isArray(events)) throw new Error("Events API response did not contain an events array.");
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted)">No recent authentication decisions recorded.</td></tr>';
      return;
    }
    tbody.innerHTML = events.map((event) => {
      const risk = event.final_risk || event.agent_risk || "UNKNOWN";
      const riskClass = risk.toLowerCase();
      const riskTag = riskClass === "high" ? "tag-high" : (riskClass === "medium" ? "tag-med" : (riskClass === "low" ? "tag-low" : "tag-web"));
      const networkRisk = event.network_risk || "UNKNOWN";
      const networkEvidence = networkRisk === "UNKNOWN"
        ? "NO MATCHING NETWORK OBSERVATION"
        : `Network risk: ${networkRisk}${event.network_attack ? ` / ${event.network_attack}` : ""}`;
      return `<tr>
        <td>${formatTimestamp(event.timestamp)}</td>
        <td>${escapeHtml(event.source || "UNKNOWN")} / AUTHENTICATION</td>
        <td><small>Event: ${escapeHtml(event.event_id || "—")}<br>Decision: ${escapeHtml(event.decision_id || "—")}</small></td>
        <td>${escapeHtml(event.device_risk || event.ml_risk || "UNKNOWN")} / Agent: ${escapeHtml(event.agent_risk || "UNKNOWN")}</td>
        <td>${escapeHtml(networkEvidence)}</td>
        <td><span class="badge-tag ${riskTag}">${escapeHtml(risk)}</span></td>
        <td>${escapeHtml(event.action_taken || "RECORD_FAILED_ATTEMPT")}</td>
      </tr>`;
    }).join("");
  } catch (error) {
    console.error("Unable to load recent shared security decisions:", error);
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--red)">Unable to load recent security decisions: ${escapeHtml(error?.message || "Unknown API error")}</td></tr>`;
  } finally {
    if (tbody.textContent.includes("Loading recent security decisions")) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--red)">Security decisions did not finish loading. Refresh to retry.</td></tr>';
    }
  }
}

// Load all owner analytics & event streams
async function loadOwnerData() {
  try {
    const [
      analyticsResult,
      healthResult,
      resetResult,
      eventsResult,
    ] = await Promise.allSettled([
      API.get("/api/owner/analytics"),
      API.get("/api/owner/health"),
      API.get("/api/reset/status"),
      API.get("/api/owner/events?limit=25"),
    ]);
    renderOwnerEventsTable(eventsResult);
    renderRecentSecurityDecisions(eventsResult);
    if (analyticsResult.status === "rejected") throw analyticsResult.reason;
    if (healthResult.status === "rejected") throw healthResult.reason;
    if (resetResult.status === "rejected") throw resetResult.reason;
    const analytics = analyticsResult.value;
    const health = healthResult.value;
    const resetData = resetResult.value;

    // Overview Stats
    const ovDoor = document.getElementById("ovDoorState");
    ovDoor.textContent = analytics.door_state;
    ovDoor.style.color = analytics.door_state === "OPEN" ? "var(--green)" : "var(--red)";

    document.getElementById("ovCredentialVersion").textContent = 
      `Credential Version: ${analytics.credential_info?.version || 1} (${analytics.credential_info?.user_alias || 'Active'})`;

    const hw = health.device_telemetry || {};
    const isOnline = hw.is_online || hw.wifi_status === "CONNECTED";
    const ovHw = document.getElementById("ovHwStatus");
    ovHw.textContent = isOnline ? "ONLINE" : "OFFLINE";
    ovHw.style.color = isOnline ? "var(--green)" : "var(--red)";
    document.getElementById("ovHwIp").textContent = `IP: ${hw.ip_address || '—'} (${hw.rssi ? hw.rssi + ' dBm' : '—'})`;

    const risk = analytics.timeline?.[0]?.agent_risk || "LOW";
    document.getElementById("ovRiskLevel").textContent = risk;
    document.getElementById("ovRiskLevel").style.color = 
      risk === "HIGH" ? "var(--red)" : (risk === "MEDIUM" ? "var(--yellow)" : "var(--green)");

    document.getElementById("ovFailedStreak").textContent = `Failed streak: ${analytics.active_failed_streak}`;

    const kem = analytics.timeline?.[0]?.pqc_kem || "ML-KEM-512";
    document.getElementById("ovPqcSuite").textContent = kem;

    // Health Telemetry
    const comps = health.components || {};
    document.getElementById("systemHealthSummary").innerHTML = `
      DB: <b>${comps.sqlite_database}</b> • 
      ML: <b>${comps.random_forest_model}</b> • 
      Agent: <b>${comps.langgraph_agent}</b> • 
      PQC: <b>${comps.pqc_subsystem}</b> • 
      ESP8266: <b>${comps.esp8266_hardware}</b>
    `;

    // Analytics Risk Bars
    const rDist = analytics.risk_distribution || {};
    const total = (rDist.LOW || 0) + (rDist.MEDIUM || 0) + (rDist.HIGH || 0) || 1;
    document.getElementById("barLow").style.width = `${((rDist.LOW || 0) / total) * 100}%`;
    document.getElementById("barMed").style.width = `${((rDist.MEDIUM || 0) / total) * 100}%`;
    document.getElementById("barHigh").style.width = `${((rDist.HIGH || 0) / total) * 100}%`;
    document.getElementById("cntLow").textContent = rDist.LOW || 0;
    document.getElementById("cntMed").textContent = rDist.MEDIUM || 0;
    document.getElementById("cntHigh").textContent = rDist.HIGH || 0;

    document.getElementById("statTotalAttempts").textContent = analytics.total_attempts;
    const rate = analytics.total_attempts > 0 ? Math.round((analytics.successful_attempts / analytics.total_attempts) * 100) : 100;
    document.getElementById("statSuccessRate").textContent = `${rate}%`;

    const alertBox = document.getElementById("statIntrusionAlert");
    if (analytics.is_locked_out || risk === "HIGH") {
      alertBox.textContent = "INTRUSION WARNING";
      alertBox.style.color = "var(--red)";
    } else {
      alertBox.textContent = "NORMAL";
      alertBox.style.color = "var(--green)";
    }

    // OTP Status
    if (resetData.active_session && resetData.otp && currentOtpSecondsRemaining <= 0) {
      displayActiveOtp(resetData.otp, resetData.remaining_seconds);
    }

  } catch (err) {
    console.error("Owner dashboard data refresh failed:", err);
  }
}

function startPolling() {
  setInterval(loadOwnerData, 3000);
}

// Initial session probe
checkOwnerAuth();
