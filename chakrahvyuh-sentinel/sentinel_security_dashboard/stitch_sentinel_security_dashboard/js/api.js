window.SentinelAPI = {
  base() {
    return (window.SENTINEL_CONFIG?.API_BASE || "https://chakravyuh-sentinel.onrender.com").replace(/\/$/, "");
  },

  async get(path, params = {}, timeoutMs = 15000) {
    const url = new URL(this.base() + path);
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url.toString(), {
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      clearTimeout(timer);
      if (!response.ok) {
        throw new Error(`API ${path} error: HTTP ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  },

  async checkHealth() {
    try {
      const res = await this.get("/", {}, 6000);
      return { online: true, data: res };
    } catch {
      return { online: false };
    }
  },

  getStats() {
    return this.get("/stats");
  },

  getStatistics() {
    return this.get("/statistics");
  },

  getAlerts(params = {}) {
    return this.get("/alerts", params);
  },

  getBlockedIps(params = {}) {
    return this.get("/blocked-ips", params);
  },

  getRequests(params = {}) {
    return this.get("/requests", params);
  },

  getSessions(params = {}) {
    return this.get("/sessions", params);
  },

  getIncidents() {
    return this.get("/incidents");
  },

  getTimeline(sessionId) {
    return this.get(`/incidents/${encodeURIComponent(sessionId)}/timeline`);
  },

  getExplanation(incidentId) {
    return this.get(`/incidents/${encodeURIComponent(incidentId)}/explanation`);
  },

  async closeIncident(incidentId) {
    const response = await fetch(`${this.base()}/incidents/${encodeURIComponent(incidentId)}/close`, {
      method: "PATCH",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`Failed to close incident: HTTP ${response.status}`);
    }
    return response.json();
  },

  getSeverityStats() {
    return this.get("/stats/severity");
  },

  getActionStats() {
    return this.get("/stats/actions");
  },

  getRateLimitStats() {
    return this.get("/rate-limit/stats");
  },
};
