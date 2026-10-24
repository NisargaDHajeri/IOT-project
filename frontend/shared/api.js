/**
 * Shared API client for Adaptive PQC Smart Door Lock Frontend.
 */

const API = {
  async get(url) {
    try {
      const res = await fetch(url, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      return data;
    } catch (err) {
      console.error(`GET ${url} failed:`, err);
      throw err;
    }
  },

  async post(url, body = {}) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.message || `HTTP ${res.status}`);
      }
      return data;
    } catch (err) {
      console.error(`POST ${url} failed:`, err);
      throw err;
    }
  },
};

window.API = API;
