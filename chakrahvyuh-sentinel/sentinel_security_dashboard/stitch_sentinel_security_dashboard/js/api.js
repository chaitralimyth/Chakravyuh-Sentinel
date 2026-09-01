window.SentinelAPI = {
  base() {
    return window.SENTINEL_CONFIG.API_BASE.replace(/\/$/, "");
  },

  async get(path, params = {}) {
    const url = new URL(this.base() + path);
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    });

    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(`API ${path} failed: ${response.status}`);
    }
    return response.json();
  },

  getStats() {
    return this.get("/stats");
  },

  getStatistics() {
    return this.get("/statistics");
  },

  getAlerts(params) {
    return this.get("/alerts", params);
  },

  getBlockedIps(params) {
    return this.get("/blocked-ips", params);
  },

  getRequests(params) {
    return this.get("/requests", params);
  },

  getSessions(params) {
    return this.get("/sessions", params);
  },
};
