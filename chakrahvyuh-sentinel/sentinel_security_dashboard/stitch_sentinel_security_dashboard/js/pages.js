window.SentinelPages = window.SentinelPages || {};
window.SentinelUI = window.SentinelUI || {};

// Reusable Toast feedback
SentinelUI.showToast = function (message, type = "info") {
  let container = document.getElementById("sentinel-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "sentinel-toast-container";
    container.className = "fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  const bg =
    type === "error"
      ? "bg-red-600 text-white"
      : type === "success"
      ? "bg-emerald-600 text-white"
      : "bg-slate-900 text-white";

  toast.className = `pointer-events-auto flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-lg text-sm font-medium transition-all duration-300 transform translate-y-2 opacity-0 ${bg}`;
  toast.innerHTML = `
    <span class="material-symbols-outlined text-[18px]">${
      type === "error" ? "error" : type === "success" ? "check_circle" : "info"
    }</span>
    <span>${message}</span>
  `;
  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove("translate-y-2", "opacity-0");
  });

  setTimeout(() => {
    toast.classList.add("opacity-0", "translate-y-2");
    setTimeout(() => toast.remove(), 300);
  }, 3500);
};

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? "—";
}

function setHTML(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function emptyRow(colspan, message, icon = "inbox") {
  return `
    <tr>
      <td colspan="${colspan}" class="px-6 py-12 text-center text-slate-500">
        <div class="flex flex-col items-center justify-center gap-2">
          <span class="material-symbols-outlined text-slate-400 text-[32px]">${icon}</span>
          <p class="font-medium text-sm text-slate-600">${message}</p>
        </div>
      </td>
    </tr>`;
}

function skeletonRows(colspan, count = 5) {
  let html = "";
  for (let i = 0; i < count; i++) {
    html += `
      <tr class="animate-pulse border-b border-slate-100">
        <td colspan="${colspan}" class="px-6 py-4">
          <div class="h-4 bg-slate-200/70 rounded w-full"></div>
        </td>
      </tr>`;
  }
  return html;
}

function updateEngineStatus(isOnline) {
  document.querySelectorAll("[data-engine-status]").forEach((el) => {
    if (isOnline) {
      el.innerHTML = `
        <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
        <span class="font-semibold text-xs tracking-wider uppercase text-emerald-700">Security Engine Online</span>
      `;
      el.className = "inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200";
    } else {
      el.innerHTML = `
        <span class="w-2 h-2 rounded-full bg-amber-500"></span>
        <span class="font-semibold text-xs tracking-wider uppercase text-amber-700">Connecting / Reconnecting</span>
      `;
      el.className = "inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-50 border border-amber-200";
    }
  });
}

// -------------------------------------------------------------
// REUSABLE ALERT DETAIL DRAWER CONTROLLER
// -------------------------------------------------------------
SentinelPages.openAlertDrawer = function (alert) {
  const F = window.SentinelFormat;
  const drawer = document.getElementById("alert-detail-drawer");
  const overlay = document.getElementById("alert-detail-overlay");
  if (!drawer || !overlay) return;

  const riskScore = alert.risk_score !== null && alert.risk_score !== undefined ? Math.round(alert.risk_score) : null;
  const severity = alert.severity ? alert.severity.toUpperCase() : null;

  setText("drawer-alert-id", `ALT-${alert.id}`);
  setText("drawer-alert-ip", alert.ip);
  setText("drawer-alert-session", alert.session_id || "None");
  setText("drawer-alert-time", F.datetime(alert.created_at));
  setText("drawer-alert-reason", alert.reason || "Suspicious traffic pattern detected by security engine.");
  setHTML("drawer-alert-prediction", F.predictionBadge(alert.prediction));
  setText("drawer-alert-confidence", F.percent(alert.confidence));
  setHTML("drawer-alert-action", F.actionBadge(alert.action));
  setHTML("drawer-alert-severity", F.severityBadge(severity));
  setHTML("drawer-alert-risk", F.riskScoreBadge(riskScore, severity));

  // Risk meter progress
  const meterEl = document.getElementById("drawer-risk-meter");
  if (meterEl) {
    if (riskScore !== null) {
      meterEl.style.width = `${Math.min(100, Math.max(0, riskScore))}%`;
    } else {
      meterEl.style.width = "0%";
    }
  }

  // Show drawer
  overlay.classList.remove("hidden");
  requestAnimationFrame(() => {
    overlay.classList.remove("opacity-0");
    drawer.classList.remove("translate-x-full");
  });

  const closeBtn = document.getElementById("close-alert-drawer");
  const closeHandler = () => {
    drawer.classList.add("translate-x-full");
    overlay.classList.add("opacity-0");
    setTimeout(() => {
      overlay.classList.add("hidden");
      closeBtn?.removeEventListener("click", closeHandler);
      overlay?.removeEventListener("click", closeHandler);
    }, 300);
  };
  closeBtn?.addEventListener("click", closeHandler);
  overlay?.addEventListener("click", (e) => {
    if (e.target === overlay) closeHandler();
  });
};

// -------------------------------------------------------------
// 1. DASHBOARD OVERVIEW PAGE
// -------------------------------------------------------------
SentinelPages.dashboard = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("recent-alerts-body");
  const refreshBtn = document.getElementById("refresh-btn");
  let activityChart = null;
  let donutChart = null;

  async function load() {
    if (tbody) tbody.innerHTML = skeletonRows(8, 4);

    try {
      const [stats, alerts, analytics, severityStats] = await Promise.all([
        SentinelAPI.getStats(),
        SentinelAPI.getAlerts({ limit: 8 }),
        SentinelAPI.getStatistics().catch(() => ({})),
        SentinelAPI.getSeverityStats().catch(() => ({})),
      ]);

      updateEngineStatus(stats.status === "running" || !!stats.total_requests);

      // 1. Update Core Metric Cards
      setText("stat-total-requests", F.number(stats.total_requests));
      setText("stat-requests-24h", `${F.number(stats.requests_24h)} in last 24h`);
      setText("stat-active-sessions", F.number(stats.active_sessions));
      setText("stat-total-alerts", F.number(stats.total_alerts));
      setText("stat-unread-alerts", `${F.number(stats.unread_alerts)} unread`);
      setText("stat-blocked-ips", F.number(stats.active_blocked_ips));

      // 2. Risk Score & Severity Display (Backend is single source of truth)
      let latestRiskScore = null;
      let latestSeverity = null;

      if (alerts && alerts.length > 0) {
        const topAlert = alerts[0];
        if (topAlert.risk_score !== null && topAlert.risk_score !== undefined) {
          latestRiskScore = Math.round(topAlert.risk_score);
        }
        if (topAlert.severity) {
          latestSeverity = topAlert.severity.toUpperCase();
        }
      }

      setText("stat-risk-score", latestRiskScore !== null ? `${latestRiskScore}` : "—");
      setHTML("stat-severity-badge", F.severityBadge(latestSeverity));
      const riskMeterEl = document.getElementById("stat-risk-meter");
      if (riskMeterEl) {
        if (latestRiskScore !== null) {
          riskMeterEl.style.width = `${Math.min(100, Math.max(0, latestRiskScore))}%`;
          if (latestRiskScore >= 80) riskMeterEl.className = "h-full rounded-full transition-all duration-500 bg-red-600";
          else if (latestRiskScore >= 60) riskMeterEl.className = "h-full rounded-full transition-all duration-500 bg-orange-500";
          else if (latestRiskScore >= 30) riskMeterEl.className = "h-full rounded-full transition-all duration-500 bg-amber-500";
          else riskMeterEl.className = "h-full rounded-full transition-all duration-500 bg-emerald-500";
        } else {
          riskMeterEl.style.width = "0%";
          riskMeterEl.className = "h-full rounded-full transition-all duration-500 bg-slate-200";
        }
      }

      // 3. Render Recent Security Alerts Table
      if (tbody) {
        if (alerts.length > 0) {
          tbody.innerHTML = alerts
            .map((alert, idx) => {
              const rScore = alert.risk_score !== null && alert.risk_score !== undefined ? Math.round(alert.risk_score) : null;
              const sev = alert.severity ? alert.severity.toUpperCase() : null;
              return `
              <tr class="hover:bg-slate-50/80 transition-colors cursor-pointer group" data-alert-index="${idx}">
                <td class="px-5 py-3.5 whitespace-nowrap">${F.severityBadge(sev)}</td>
                <td class="px-5 py-3.5 whitespace-nowrap">${F.riskScoreBadge(rScore, sev)}</td>
                <td class="px-5 py-3.5 whitespace-nowrap font-mono text-xs font-semibold text-slate-800">${alert.ip}</td>
                <td class="px-5 py-3.5 whitespace-nowrap">${F.predictionBadge(alert.prediction)}</td>
                <td class="px-5 py-3.5 whitespace-nowrap font-mono text-xs text-slate-600">${F.percent(alert.confidence)}</td>
                <td class="px-5 py-3.5 whitespace-nowrap">${F.actionBadge(alert.action)}</td>
                <td class="px-5 py-3.5 text-xs text-slate-600 max-w-[240px] truncate" title="${alert.reason || ""}">${F.truncate(alert.reason, 36)}</td>
                <td class="px-5 py-3.5 whitespace-nowrap text-xs text-slate-500">${F.relativeTime(alert.created_at)}</td>
                <td class="px-5 py-3.5 text-right whitespace-nowrap">
                  <span class="inline-flex items-center gap-1 text-xs ${alert.is_read ? "text-slate-400" : "text-amber-600 font-medium"}">
                    <span class="w-1.5 h-1.5 rounded-full ${alert.is_read ? "bg-slate-300" : "bg-amber-500"}"></span>
                    ${alert.is_read ? "Read" : "New"}
                  </span>
                </td>
              </tr>`;
            })
            .join("");

          // Attach click listeners to open drawer
          tbody.querySelectorAll("[data-alert-index]").forEach((row) => {
            row.addEventListener("click", () => {
              const idx = parseInt(row.getAttribute("data-alert-index"), 10);
              if (alerts[idx]) SentinelPages.openAlertDrawer(alerts[idx]);
            });
          });
        } else {
          tbody.innerHTML = emptyRow(9, "No security alerts detected. Protected website traffic is safe.", "verified_user");
        }
      }

      // 4. Activity Overview Chart (Chart.js)
      const activityCanvas = document.getElementById("activityChart");
      if (activityCanvas && window.Chart) {
        const reqDays = analytics.requests_by_day || [];
        const blockDays = analytics.blocked_by_day || [];
        const labels = reqDays.length > 0 ? reqDays.map((d) => d.date) : ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        const reqData = reqDays.length > 0 ? reqDays.map((d) => d.count) : [0, 0, 0, 0, 0, 0, stats.total_requests || 0];
        const blockMap = {};
        blockDays.forEach((b) => (blockMap[b.date] = b.count));
        const blockData = labels.map((date) => blockMap[date] || 0);

        if (activityChart) activityChart.destroy();
        activityChart = new Chart(activityCanvas, {
          type: "line",
          data: {
            labels: labels,
            datasets: [
              {
                label: "Requests",
                data: reqData,
                borderColor: "#0058be",
                backgroundColor: "rgba(0, 88, 190, 0.08)",
                borderWidth: 2,
                fill: true,
                tension: 0.35,
                pointRadius: 3,
                pointHoverRadius: 5,
              },
              {
                label: "Blocked Attacks",
                data: blockData,
                borderColor: "#dc2626",
                backgroundColor: "rgba(220, 38, 38, 0.1)",
                borderWidth: 2,
                fill: true,
                tension: 0.35,
                pointRadius: 3,
                pointHoverRadius: 5,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: "index", intersect: false },
            plugins: {
              legend: {
                display: true,
                position: "top",
                align: "end",
                labels: { boxWidth: 10, font: { family: "Inter", size: 12 } },
              },
              tooltip: { padding: 10, cornerRadius: 8 },
            },
            scales: {
              x: { grid: { display: false }, ticks: { font: { family: "Inter", size: 11 } } },
              y: {
                beginAtZero: true,
                grid: { color: "#f1f5f9" },
                ticks: { precision: 0, font: { family: "Inter", size: 11 } },
              },
            },
          },
        });
      }

      // 5. Threat Detection Donut (Chart.js)
      const donutCanvas = document.getElementById("decisionDonutChart");
      if (donutCanvas && window.Chart) {
        const dist = analytics.decision_distribution || {};
        const normalCount = dist.normal || (stats.total_requests ? Math.max(0, stats.total_requests - stats.total_alerts) : 1);
        const attackCount = dist.attacker || stats.total_alerts || 0;
        const total = normalCount + attackCount;

        setText("decision-total", F.number(total));
        setText("decision-normal-pct", `${Math.round((normalCount / (total || 1)) * 100)}% Normal`);
        setText("decision-attacker-pct", `${Math.round((attackCount / (total || 1)) * 100)}% Threat`);

        if (donutChart) donutChart.destroy();
        donutChart = new Chart(donutCanvas, {
          type: "doughnut",
          data: {
            labels: ["Normal Traffic", "Attacker Threats"],
            datasets: [
              {
                data: [normalCount, attackCount],
                backgroundColor: ["#10b981", "#dc2626"],
                borderWidth: 2,
                borderColor: "#ffffff",
                hoverOffset: 4,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "75%",
            plugins: {
              legend: { display: false },
              tooltip: { padding: 8, cornerRadius: 6 },
            },
          },
        });
      }
    } catch (err) {
      console.error("Dashboard load failed:", err);
      updateEngineStatus(false);
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td colspan="9" class="px-6 py-8 text-center">
              <div class="inline-flex flex-col items-center gap-3">
                <span class="material-symbols-outlined text-red-500 text-[32px]">error</span>
                <p class="text-sm font-medium text-slate-700">Unable to load security data from API</p>
                <button id="retry-dashboard-btn" class="px-3 py-1.5 bg-slate-900 text-white rounded-md text-xs font-semibold hover:bg-slate-800 transition-colors">
                  Retry
                </button>
              </div>
            </td>
          </tr>`;
        document.getElementById("retry-dashboard-btn")?.addEventListener("click", load);
      }
      SentinelUI.showToast("Failed to connect to Chakravyuh API", "error");
    }
  }

  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      refreshBtn.classList.add("opacity-60", "pointer-events-none");
      const icon = refreshBtn.querySelector(".material-symbols-outlined");
      if (icon) icon.classList.add("animate-spin");
      await load();
      SentinelUI.showToast("Security data refreshed", "success");
      setTimeout(() => {
        refreshBtn.classList.remove("opacity-60", "pointer-events-none");
        if (icon) icon.classList.remove("animate-spin");
      }, 500);
    });
  }

  await load();
};

// -------------------------------------------------------------
// 2. SECURITY ALERTS PAGE
// -------------------------------------------------------------
SentinelPages.alerts = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("alerts-table-body");
  const countLabel = document.getElementById("alerts-count-label");
  const refreshBtn = document.getElementById("refresh-alerts-btn");
  let allAlerts = [];

  const filterIp = document.getElementById("filter-ip");
  const filterPrediction = document.getElementById("filter-prediction");
  const filterSeverity = document.getElementById("filter-severity");
  const filterAction = document.getElementById("filter-action");
  const filterRead = document.getElementById("filter-read");
  const clearBtn = document.getElementById("clear-filters-btn");

  function applyFilters() {
    const ipQuery = (filterIp?.value || "").trim().toLowerCase();
    const predQuery = (filterPrediction?.value || "").toLowerCase();
    const sevQuery = (filterSeverity?.value || "").toUpperCase();
    const actQuery = (filterAction?.value || "").toUpperCase();
    const readQuery = filterRead?.value || "";

    const filtered = allAlerts.filter((a) => {
      if (ipQuery && !((a.ip || "").toLowerCase().includes(ipQuery) || (a.session_id || "").toLowerCase().includes(ipQuery))) {
        return false;
      }
      if (predQuery && (a.prediction || "").toLowerCase() !== predQuery) return false;
      const rScore = a.risk_score !== null && a.risk_score !== undefined ? Math.round(a.risk_score) : null;
      const sev = a.severity ? a.severity.toUpperCase() : null;
      if (sevQuery && sev !== sevQuery) return false;
      if (actQuery && (a.action || "").toUpperCase() !== actQuery) return false;
      if (readQuery === "read" && !a.is_read) return false;
      if (readQuery === "unread" && a.is_read) return false;
      return true;
    });

    if (countLabel) {
      countLabel.textContent = `Showing ${filtered.length} of ${allAlerts.length} alerts`;
    }

    if (!tbody) return;
    if (filtered.length === 0) {
      tbody.innerHTML = emptyRow(11, "No security alerts match the selected filters.", "filter_alt_off");
      return;
    }

    tbody.innerHTML = filtered
      .map((a, idx) => {
        const rScore = a.risk_score !== null && a.risk_score !== undefined ? Math.round(a.risk_score) : null;
        const sev = a.severity ? a.severity.toUpperCase() : null;
        return `
        <tr class="hover:bg-slate-50 transition-colors cursor-pointer group" data-alert-row="${idx}">
          <td class="px-4 py-3.5 font-mono text-xs font-semibold text-slate-800">ALT-${a.id}</td>
          <td class="px-4 py-3.5 font-mono text-xs font-semibold text-slate-800">${a.ip}</td>
          <td class="px-4 py-3.5 font-mono text-xs text-slate-500">${F.sessionIdShort(a.session_id)}</td>
          <td class="px-4 py-3.5 whitespace-nowrap">${F.predictionBadge(a.prediction)}</td>
          <td class="px-4 py-3.5 font-mono text-xs text-slate-600">${F.percent(a.confidence)}</td>
          <td class="px-4 py-3.5 whitespace-nowrap">${F.riskScoreBadge(rScore, sev)}</td>
          <td class="px-4 py-3.5 whitespace-nowrap">${F.severityBadge(sev)}</td>
          <td class="px-4 py-3.5 whitespace-nowrap">${F.actionBadge(a.action)}</td>
          <td class="px-4 py-3.5 text-xs text-slate-600 max-w-[220px] truncate" title="${a.reason || ""}">${F.truncate(a.reason, 36)}</td>
          <td class="px-4 py-3.5 whitespace-nowrap font-mono text-xs text-slate-500">${F.datetime(a.created_at)}</td>
          <td class="px-4 py-3.5 whitespace-nowrap">
            <span class="inline-flex items-center gap-1.5 text-xs ${a.is_read ? "text-slate-400" : "text-amber-600 font-semibold"}">
              <span class="w-1.5 h-1.5 rounded-full ${a.is_read ? "bg-slate-300" : "bg-amber-500"}"></span>
              ${a.is_read ? "Read" : "Unread"}
            </span>
          </td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll("[data-alert-row]").forEach((row) => {
      row.addEventListener("click", () => {
        const idx = parseInt(row.getAttribute("data-alert-row"), 10);
        if (filtered[idx]) SentinelPages.openAlertDrawer(filtered[idx]);
      });
    });
  }

  async function load() {
    if (tbody) tbody.innerHTML = skeletonRows(11, 5);

    try {
      const [stats, alerts, severityStats] = await Promise.all([
        SentinelAPI.getStats(),
        SentinelAPI.getAlerts({ limit: 200 }),
        SentinelAPI.getSeverityStats().catch(() => ({})),
      ]);

      allAlerts = alerts;

      // Summary counts
      setText("alert-stat-total", F.number(stats.total_alerts || alerts.length));
      setText("alert-stat-unread", F.number(stats.unread_alerts || alerts.filter((a) => !a.is_read).length));
      const criticalCount = severityStats?.CRITICAL ?? alerts.filter((a) => (a.severity || "").toUpperCase() === "CRITICAL").length;
      const highCount = severityStats?.HIGH ?? alerts.filter((a) => (a.severity || "").toUpperCase() === "HIGH").length;
      setText("alert-stat-critical", F.number(criticalCount));
      setText("alert-stat-high", F.number(highCount));
      setText("alert-stat-blocks", F.number(alerts.filter((a) => (a.action || "").toUpperCase() === "BLOCK").length));

      applyFilters();
    } catch (err) {
      console.error(err);
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td colspan="11" class="px-6 py-8 text-center text-red-600">
              <p class="font-medium">Unable to load security alerts.</p>
              <button id="retry-alerts-btn" class="mt-2 px-3 py-1 bg-slate-900 text-white rounded text-xs">Retry</button>
            </td>
          </tr>`;
        document.getElementById("retry-alerts-btn")?.addEventListener("click", load);
      }
    }
  }

  [filterIp, filterPrediction, filterSeverity, filterAction, filterRead].forEach((el) => {
    el?.addEventListener("input", applyFilters);
    el?.addEventListener("change", applyFilters);
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (filterIp) filterIp.value = "";
      if (filterPrediction) filterPrediction.value = "";
      if (filterSeverity) filterSeverity.value = "";
      if (filterAction) filterAction.value = "";
      if (filterRead) filterRead.value = "";
      applyFilters();
      SentinelUI.showToast("Filters reset", "info");
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      await load();
      SentinelUI.showToast("Alerts refreshed", "success");
    });
  }

  await load();
};

// -------------------------------------------------------------
// 3. BLOCKED IPS PAGE
// -------------------------------------------------------------
SentinelPages["blocked-ips"] = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("blocked-ips-body");
  const countLabel = document.getElementById("blocked-count-label");
  const filterIp = document.getElementById("blocked-search-ip");
  const filterStatus = document.getElementById("blocked-status-filter");
  const refreshBtn = document.getElementById("refresh-blocked-btn");
  let allBlocks = [];

  function applyFilters() {
    const q = (filterIp?.value || "").trim().toLowerCase();
    const st = filterStatus?.value || "";

    const filtered = allBlocks.filter((b) => {
      if (q && !(b.ip || "").toLowerCase().includes(q)) return false;
      if (st === "active" && !b.is_active) return false;
      if (st === "expired" && b.is_active) return false;
      return true;
    });

    if (countLabel) {
      countLabel.textContent = `Showing ${filtered.length} of ${allBlocks.length} records`;
    }

    if (!tbody) return;
    if (filtered.length === 0) {
      tbody.innerHTML = emptyRow(8, "No blocked IP addresses match the criteria.", "check_circle");
      return;
    }

    tbody.innerHTML = filtered
      .map((b) => {
        return `
        <tr class="hover:bg-slate-50 transition-colors">
          <td class="px-5 py-3.5 font-mono text-xs font-bold text-slate-900">${b.ip}</td>
          <td class="px-5 py-3.5 whitespace-nowrap">${F.predictionBadge(b.prediction)}</td>
          <td class="px-5 py-3.5 whitespace-nowrap font-mono text-xs text-slate-600">${F.percent(b.confidence)}</td>
          <td class="px-5 py-3.5 whitespace-nowrap">${F.actionBadge("BLOCK")}</td>
          <td class="px-5 py-3.5 whitespace-nowrap">
            <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
              b.is_active
                ? "bg-red-50 text-red-700 border border-red-200"
                : "bg-slate-100 text-slate-600 border border-slate-200"
            }">
              <span class="w-1.5 h-1.5 rounded-full ${b.is_active ? "bg-red-600 animate-pulse" : "bg-slate-400"}"></span>
              ${b.is_active ? "ACTIVE" : "EXPIRED"}
            </span>
          </td>
          <td class="px-5 py-3.5 text-xs text-slate-600 max-w-[200px] truncate" title="${b.reason || ""}">${F.truncate(b.reason, 36)}</td>
          <td class="px-5 py-3.5 font-mono text-xs text-slate-500 whitespace-nowrap">${F.datetime(b.blocked_at)}</td>
          <td class="px-5 py-3.5 font-mono text-xs text-slate-500 whitespace-nowrap">${b.blocked_until ? F.datetime(b.blocked_until) : "Permanent"}</td>
        </tr>`;
      })
      .join("");
  }

  async function load() {
    if (tbody) tbody.innerHTML = skeletonRows(8, 4);

    try {
      const blocks = await SentinelAPI.getBlockedIps({ active_only: false, limit: 200 });
      allBlocks = blocks;
      const active = blocks.filter((b) => b.is_active);
      const now = Date.now();
      const dayAgo = now - 24 * 60 * 60 * 1000;
      const sixHours = now + 6 * 60 * 60 * 1000;

      setText("blocked-stat-active", F.number(active.length));
      setText(
        "blocked-stat-recent",
        F.number(blocks.filter((b) => new Date(b.blocked_at).getTime() >= dayAgo).length)
      );
      setText(
        "blocked-stat-expiring",
        F.number(
          active.filter((b) => b.blocked_until && new Date(b.blocked_until).getTime() <= sixHours).length
        )
      );

      applyFilters();
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(8, "Unable to load blocked IPs. Please check API connection.", "error");
    }
  }

  filterIp?.addEventListener("input", applyFilters);
  filterStatus?.addEventListener("change", applyFilters);
  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      await load();
      SentinelUI.showToast("Blocked IPs refreshed", "success");
    });
  }

  await load();
};

// -------------------------------------------------------------
// 4. REQUEST MONITORING PAGE
// -------------------------------------------------------------
SentinelPages.requests = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("requests-table-body");
  const countLabel = document.getElementById("requests-count-label");
  const searchInput = document.getElementById("request-search");
  const methodFilter = document.getElementById("request-method-filter");
  const statusFilter = document.getElementById("request-status-filter");
  const refreshBtn = document.getElementById("refresh-requests-btn");
  let allRequests = [];

  function applyFilters() {
    const q = (searchInput?.value || "").trim().toLowerCase();
    const method = (methodFilter?.value || "").toUpperCase();
    const statusRange = statusFilter?.value || "";

    const filtered = allRequests.filter((r) => {
      if (q && !((r.ip || "").toLowerCase().includes(q) || (r.endpoint || "").toLowerCase().includes(q))) {
        return false;
      }
      if (method && (r.method || "").toUpperCase() !== method) return false;
      if (statusRange) {
        const sc = Number(r.status_code);
        if (statusRange === "2xx" && (sc < 200 || sc >= 300)) return false;
        if (statusRange === "3xx" && (sc < 300 || sc >= 400)) return false;
        if (statusRange === "4xx" && (sc < 400 || sc >= 500)) return false;
        if (statusRange === "5xx" && sc < 500) return false;
      }
      return true;
    });

    if (countLabel) {
      countLabel.textContent = `Showing ${filtered.length} of ${allRequests.length} recent requests`;
    }

    if (!tbody) return;
    if (filtered.length === 0) {
      tbody.innerHTML = emptyRow(7, "No request logs match the selected filters.", "search_off");
      return;
    }

    tbody.innerHTML = filtered
      .map(
        (r) => `
        <tr class="hover:bg-slate-50 transition-colors">
          <td class="px-5 py-3 font-mono text-xs text-slate-500 whitespace-nowrap">${F.datetime(r.timestamp)}</td>
          <td class="px-5 py-3 font-mono text-xs font-semibold text-slate-800 whitespace-nowrap">${r.ip}</td>
          <td class="px-5 py-3 whitespace-nowrap">${F.methodBadge(r.method)}</td>
          <td class="px-5 py-3 font-mono text-xs text-slate-800 max-w-[280px] truncate" title="${r.endpoint}">${r.endpoint}</td>
          <td class="px-5 py-3 whitespace-nowrap">${F.statusCodeBadge(r.status_code)}</td>
          <td class="px-5 py-3 font-mono text-xs text-slate-600 whitespace-nowrap text-right">${Math.round(r.response_time_ms || 0)}ms</td>
          <td class="px-5 py-3 font-mono text-xs text-slate-500 whitespace-nowrap">${F.sessionIdShort(r.session_id)}</td>
        </tr>`
      )
      .join("");
  }

  async function load() {
    if (tbody) tbody.innerHTML = skeletonRows(7, 6);

    try {
      const logs = await SentinelAPI.getRequests({ limit: 100 });
      allRequests = logs;
      applyFilters();
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(7, "Unable to load request logs from API.", "error");
    }
  }

  searchInput?.addEventListener("input", applyFilters);
  methodFilter?.addEventListener("change", applyFilters);
  statusFilter?.addEventListener("change", applyFilters);
  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      await load();
      SentinelUI.showToast("Requests refreshed", "success");
    });
  }

  await load();
};

// -------------------------------------------------------------
// 5. SESSION MONITORING PAGE
// -------------------------------------------------------------
SentinelPages.sessions = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("sessions-table-body");
  const countLabel = document.getElementById("sessions-count-label");
  const searchInput = document.getElementById("session-search");
  const statusFilter = document.getElementById("session-status-filter");
  const refreshBtn = document.getElementById("refresh-sessions-btn");
  let allSessions = [];
  let selectedSession = null;

  async function showSessionDetails(session) {
    selectedSession = session;
    setText("session-detail-id", session.session_id);
    setText("session-detail-ip", session.ip);
    setHTML("session-detail-status", F.sessionStatusBadge(session.status));
    setText("session-detail-requests", F.number(session.request_count));
    setText("session-detail-duration", F.duration(session.duration_seconds));
    setText("session-detail-start", F.datetime(session.started_at));
    setText("session-detail-activity", F.datetime(session.last_activity));

    // Fetch live session timeline events from Sentinel backend
    const timelineContainer = document.getElementById("session-detail-timeline");
    if (timelineContainer) {
      timelineContainer.innerHTML = `
        <div class="py-4 text-center text-slate-400 text-xs flex items-center justify-center gap-2">
          <span class="w-3 h-3 border-2 border-slate-300 border-t-transparent rounded-full animate-spin"></span>
          Loading timeline…
        </div>`;

      try {
        const timelineData = await SentinelAPI.getTimeline(session.session_id);
        const events = timelineData.timeline || [];

        if (events.length === 0) {
          timelineContainer.innerHTML = `
            <div class="p-3 text-center text-slate-400 text-xs">
              No security events recorded for this session.
            </div>`;
        } else {
          timelineContainer.innerHTML = events
            .slice(-10) // Show last 10 chronological events
            .map((evt) => {
              const isAlert = evt.event_type === "SECURITY_ALERT" || evt.event_type === "IP_BLOCKED";
              const isErr = evt.event_type === "REQUEST_ERROR";
              const icon = isAlert ? "warning" : isErr ? "error" : "swap_horiz";
              const iconColor = isAlert ? "text-red-600 bg-red-50" : isErr ? "text-amber-600 bg-amber-50" : "text-blue-600 bg-blue-50";

              return `
              <div class="flex items-start gap-3 text-xs">
                <div class="w-6 h-6 rounded-full flex items-center justify-center shrink-0 ${iconColor}">
                  <span class="material-symbols-outlined text-[14px]">${icon}</span>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="font-semibold text-slate-800">${evt.event_type.replace(/_/g, " ")}</div>
                  <div class="text-slate-600 truncate">${evt.description || evt.endpoint || "—"}</div>
                  <div class="text-[10px] text-slate-400 font-mono mt-0.5">${F.time(evt.timestamp)}</div>
                </div>
              </div>`;
            })
            .join("");
        }
      } catch (err) {
        timelineContainer.innerHTML = `
          <div class="p-2 text-center text-slate-400 text-xs">
            Standard user session (${session.request_count} total requests).
          </div>`;
      }
    }
  }

  function applyFilters() {
    const q = (searchInput?.value || "").trim().toLowerCase();
    const st = (statusFilter?.value || "").toLowerCase();

    const filtered = allSessions.filter((s) => {
      if (q && !((s.ip || "").toLowerCase().includes(q) || (s.session_id || "").toLowerCase().includes(q))) {
        return false;
      }
      if (st && (s.status || "").toLowerCase() !== st) return false;
      return true;
    });

    if (countLabel) {
      countLabel.textContent = `Showing ${filtered.length} of ${allSessions.length} sessions`;
    }

    if (!tbody) return;
    if (filtered.length === 0) {
      tbody.innerHTML = emptyRow(7, "No sessions found matching filters.", "group_off");
      return;
    }

    tbody.innerHTML = filtered
      .map(
        (s, idx) => `
        <tr class="hover:bg-slate-50 transition-colors cursor-pointer group ${selectedSession?.session_id === s.session_id ? "bg-blue-50/50" : ""}" data-session-index="${idx}">
          <td class="px-5 py-3 font-mono text-xs font-semibold text-slate-800">${F.sessionIdShort(s.session_id)}</td>
          <td class="px-5 py-3 font-mono text-xs font-semibold text-slate-800">${s.ip}</td>
          <td class="px-5 py-3 font-mono text-xs text-right font-medium text-slate-800">${F.number(s.request_count)}</td>
          <td class="px-5 py-3 font-mono text-xs text-slate-500 whitespace-nowrap">${F.duration(s.duration_seconds)}</td>
          <td class="px-5 py-3 font-mono text-xs text-slate-500 whitespace-nowrap">${F.time(s.started_at)}</td>
          <td class="px-5 py-3 font-mono text-xs text-slate-500 whitespace-nowrap">${F.relativeTime(s.last_activity)}</td>
          <td class="px-5 py-3 whitespace-nowrap">${F.sessionStatusBadge(s.status)}</td>
        </tr>`
      )
      .join("");

    tbody.querySelectorAll("[data-session-index]").forEach((row) => {
      row.addEventListener("click", () => {
        const idx = parseInt(row.getAttribute("data-session-index"), 10);
        if (filtered[idx]) {
          showSessionDetails(filtered[idx]);
          tbody.querySelectorAll("tr").forEach((r) => r.classList.remove("bg-blue-50/50"));
          row.classList.add("bg-blue-50/50");
        }
      });
    });
  }

  async function load() {
    if (tbody) tbody.innerHTML = skeletonRows(7, 5);

    try {
      const sessions = await SentinelAPI.getSessions({ limit: 100 });
      allSessions = sessions;

      const active = sessions.filter((s) => s.status === "active").length;
      const closed = sessions.filter((s) => s.status === "closed").length;
      const blocked = sessions.filter((s) => s.status === "blocked").length;

      setText("session-stat-active", F.number(active));
      setText("session-stat-closed", F.number(closed));
      setText("session-stat-blocked", F.number(blocked));

      applyFilters();

      if (sessions.length > 0 && !selectedSession) {
        showSessionDetails(sessions[0]);
      }
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(7, "Unable to load sessions from API.", "error");
    }
  }

  searchInput?.addEventListener("input", applyFilters);
  statusFilter?.addEventListener("change", applyFilters);
  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      await load();
      SentinelUI.showToast("Sessions refreshed", "success");
    });
  }

  await load();
};
