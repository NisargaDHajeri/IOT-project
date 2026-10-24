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

async function readNetworkCsvFeatures(file, dataRowNumber) {
  if (!Number.isSafeInteger(dataRowNumber) || dataRowNumber < 1) {
    throw new Error("Choose a positive CSV data row number.");
  }

  const reader = file.stream().getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let lineNumber = 0;

  const parseLine = (line) => {
    const fields = line.replace(/\r$/, "").split(",");
    if (lineNumber === 0) {
      if (
        fields.length !== NETWORK_FEATURE_COLUMNS.length ||
        fields.some((name, index) => name !== NETWORK_FEATURE_COLUMNS[index])
      ) {
        throw new Error("CSV columns must match the 39 CICIoT network features in model order.");
      }
      lineNumber += 1;
      return null;
    }

    if (lineNumber !== dataRowNumber) {
      lineNumber += 1;
      return null;
    }
    if (fields.length !== NETWORK_FEATURE_COLUMNS.length) {
      throw new Error(`CSV row ${dataRowNumber} does not contain exactly 39 feature values.`);
    }

    const features = {};
    for (let index = 0; index < NETWORK_FEATURE_COLUMNS.length; index += 1) {
      const value = Number(fields[index].trim());
      if (!fields[index].trim() || !Number.isFinite(value)) {
        throw new Error(`CSV row ${dataRowNumber} has a non-numeric value for ${NETWORK_FEATURE_COLUMNS[index]}.`);
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
        const line = buffer.slice(0, newlineIndex);
        buffer = buffer.slice(newlineIndex + 1);
        const features = parseLine(line);
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

  throw new Error(`CSV does not contain data row ${dataRowNumber}.`);
}

async function initializeOfflineAssessment() {
  const status = document.getElementById("offlineAuthStatus");
  const form = document.getElementById("offlineNetworkAssessmentForm");
  try {
    const owner = await API.get("/api/owner/status");
    if (!owner.authenticated) {
      status.textContent = "Owner login required. Sign in from the Owner Console, then reopen this page.";
      return;
    }
    status.textContent = "Owner authenticated. Offline CSV assessment is ready.";
    form.hidden = false;
  } catch (error) {
    status.textContent = `Unable to verify owner session: ${error.message || "API unavailable"}`;
  }
}

document.getElementById("offlineNetworkAssessmentForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = document.getElementById("offlineNetworkCsvFile").files[0];
  const rowNumber = Number(document.getElementById("offlineNetworkCsvRow").value);
  const button = document.getElementById("offlineNetworkCsvSubmit");
  const status = document.getElementById("offlineNetworkAssessmentStatus");

  if (!file) {
    status.textContent = "Choose a CICIoT CSV file before submitting.";
    return;
  }

  button.disabled = true;
  status.textContent = "Reading supplied/offline CSV row and running the network model...";
  try {
    const networkFeatures = await readNetworkCsvFeatures(file, rowNumber);
    const result = await API.post("/api/network/analyze", {
      network_features: networkFeatures,
    });
    const prediction = result.network_prediction || {};
    const confidence = prediction.max_confidence == null
      ? "confidence unavailable"
      : `${(Number(prediction.max_confidence) * 100).toFixed(1)}% confidence`;
    status.textContent = `Offline CSV row ${rowNumber} recorded: ${result.network_risk} / ${prediction.predicted_attack || "unknown"} (${confidence}). Decision ${result.decision_id || "unavailable"}.`;
  } catch (error) {
    status.textContent = error.message || "Unable to analyze the offline CSV row.";
  } finally {
    button.disabled = false;
  }
});

initializeOfflineAssessment();
