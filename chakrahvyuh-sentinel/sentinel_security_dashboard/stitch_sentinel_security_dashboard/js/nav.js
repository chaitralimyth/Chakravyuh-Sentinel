window.SentinelNav = {
  pages: {
    dashboard: "../dashboard_overview_project_aligned/code.html",
    alerts: "../security_alerts_project_aligned/code.html",
    "blocked-ips": "../agent_response_blocked_ips/code.html",
    requests: "../request_logs_sentinel_pipeline/code.html",
    sessions: "../session_monitoring_project_aligned/code.html",
    analytics: "../behavior_analysis_ml_status/code.html",
  },

  init() {
    const current = document.body.dataset.page;
    document.querySelectorAll("[data-nav]").forEach((link) => {
      const target = link.getAttribute("data-nav");
      if (this.pages[target]) {
        link.setAttribute("href", this.pages[target]);
      }
      if (target === current) {
        link.classList.add("nav-item-active");
      }
    });

    // Mobile navigation toggle if present
    const mobileToggle = document.getElementById("mobile-menu-toggle");
    const sidebar = document.getElementById("sentinel-sidebar");
    if (mobileToggle && sidebar) {
      mobileToggle.addEventListener("click", () => {
        sidebar.classList.toggle("hidden");
        sidebar.classList.toggle("fixed");
        sidebar.classList.toggle("z-50");
      });
    }
  },
};