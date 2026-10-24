/**
 * Shared formatting and UI helper utilities.
 */

function formatTimestamp(isoString) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d)) return String(isoString);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) + 
           " (" + d.toLocaleDateString() + ")";
  } catch (e) {
    return String(isoString);
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showToast(message, type = "info", duration = 4000) {
  let toastContainer = document.getElementById("toast-container");
  if (!toastContainer) {
    toastContainer = document.createElement("div");
    toastContainer.id = "toast-container";
    toastContainer.style.position = "fixed";
    toastContainer.style.bottom = "24px";
    toastContainer.style.right = "24px";
    toastContainer.style.zIndex = "9999";
    toastContainer.style.display = "flex";
    toastContainer.style.flexDirection = "column";
    toastContainer.style.gap = "10px";
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement("div");
  toast.className = `toast-msg toast-${type}`;
  toast.style.padding = "12px 20px";
  toast.style.borderRadius = "10px";
  toast.style.fontSize = "13px";
  toast.style.fontWeight = "600";
  toast.style.color = "#fff";
  toast.style.backdropFilter = "blur(10px)";
  toast.style.border = "1px solid rgba(255,255,255,0.15)";
  toast.style.boxShadow = "0 8px 24px rgba(0,0,0,0.4)";
  toast.style.transition = "all 0.3s ease";

  if (type === "success") {
    toast.style.background = "rgba(74, 222, 128, 0.25)";
    toast.style.borderColor = "rgba(74, 222, 128, 0.5)";
    toast.style.color = "#4ade80";
  } else if (type === "error" || type === "danger") {
    toast.style.background = "rgba(255, 95, 115, 0.25)";
    toast.style.borderColor = "rgba(255, 95, 115, 0.5)";
    toast.style.color = "#ff5f73";
  } else if (type === "warn") {
    toast.style.background = "rgba(250, 204, 21, 0.25)";
    toast.style.borderColor = "rgba(250, 204, 21, 0.5)";
    toast.style.color = "#facc15";
  } else {
    toast.style.background = "rgba(109, 124, 255, 0.25)";
    toast.style.borderColor = "rgba(109, 124, 255, 0.5)";
    toast.style.color = "#aeb8ff";
  }

  toast.textContent = message;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

window.formatTimestamp = formatTimestamp;
window.escapeHtml = escapeHtml;
window.showToast = showToast;
