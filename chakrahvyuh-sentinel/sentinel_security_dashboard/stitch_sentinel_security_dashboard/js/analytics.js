window.SentinelPages = window.SentinelPages || {};

SentinelPages.analytics = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("assessments-body");
  const refreshBtn = document.getElementById("refresh-analytics-btn");

  const chartInstances = {};

  function destroyCharts() {
    Object.keys(chartInstances).forEach((key) => {
      if (chartInstances[key]) {
        chartInstances[key].destroy();
        delete chartInstances[key];
      }
    });
  }

  async function load() {
    if (tbody) {
      tbody.innerHTML = `
        <tr class="animate-pulse">
          <td colspan="6" class="py-8 text-center text-slate-400">Loading behavioral assessments…</td>
        </tr>`;
    }

    try {
      const [stats, analytics, alerts, sessions] = await Promise.all([
        SentinelAPI.getStats(),
        SentinelAPI.getStatistics().catch(() => ({})),
        SentinelAPI.getAlerts({ limit: 12 }).catch(() => []),
        SentinelAPI.getSessions({ limit: 12 }).catch(() => []),
      ]);

      setText("analytics-total-requests", F.number(stats.total_requests));
      setText("analytics-total-alerts", F.number(stats.total_alerts));
      setText("analytics-blocked-ips", F.number(stats.active_blocked_ips));
      setText("analytics-active-sessions", F.number(stats.active_sessions));

      if (!window.Chart) return;
      destroyCharts();

      const gridColor = "#f1f5f9";
      const brandBlue = "#0058be";
      const brandRed = "#dc2626";
      const brandGreen = "#10b981";
      const brandTeal = "#0d9488";
      const brandIndigo = "#4f46e5";

      Chart.defaults.font.family = "'Inter', sans-serif";
      Chart.defaults.color = "#64748b";

      // 1. Requests Over Time
      const requestsByDay = analytics.requests_by_day || [];
      const reqCanvas = document.getElementById("requestsChart");
      if (reqCanvas) {
        chartInstances.requests = new Chart(reqCanvas, {
          type: "line",
          data: {
            labels: requestsByDay.length > 0 ? requestsByDay.map((d) => d.date) : ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            datasets: [
              {
                label: "Requests",
                data: requestsByDay.length > 0 ? requestsByDay.map((d) => d.count) : [0, 0, 0, 0, 0, 0, stats.total_requests || 0],
                borderColor: brandBlue,
                backgroundColor: "rgba(0, 88, 190, 0.08)",
                fill: true,
                tension: 0.35,
                borderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 6,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: { padding: 10, cornerRadius: 8 },
            },
            scales: {
              x: { grid: { display: false }, ticks: { font: { size: 11 } } },
              y: { beginAtZero: true, grid: { color: gridColor }, ticks: { font: { size: 11 } } },
            },
          },
        });
      }

      // 2. Normal vs. Attacker Ratio
      const pieCanvas = document.getElementById("trafficPieChart");
      if (pieCanvas) {
        const dist = analytics.decision_distribution || {};
        const normalCount = dist.normal || (stats.total_requests ? Math.max(0, stats.total_requests - stats.total_alerts) : 1);
        const attackCount = dist.attacker || stats.total_alerts || 0;
        const total = normalCount + attackCount;

        setText("analytics-normal-pct", `${Math.round((normalCount / (total || 1)) * 100)}% Normal`);
        setText("analytics-attacker-pct", `${Math.round((attackCount / (total || 1)) * 100)}% Attacker`);

        chartInstances.pie = new Chart(pieCanvas, {
          type: "doughnut",
          data: {
            labels: ["Normal Traffic", "Attacker Threats"],
            datasets: [
              {
                data: [normalCount, attackCount],
                backgroundColor: [brandGreen, brandRed],
                borderWidth: 2,
                borderColor: "#ffffff",
                hoverOffset: 4,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "72%",
            plugins: {
              legend: { display: false },
              tooltip: { padding: 8, cornerRadius: 6 },
            },
          },
        });
      }

      // 3. Blocked IPs Trend
      const blockedCanvas = document.getElementById("blockedIpsChart");
      if (blockedCanvas) {
        const blockedByDay = analytics.blocked_by_day || [];
        chartInstances.blocked = new Chart(blockedCanvas, {
          type: "bar",
          data: {
            labels: blockedByDay.length > 0 ? blockedByDay.map((d) => d.date) : ["Recent"],
            datasets: [
              {
                label: "Blocked IPs",
                data: blockedByDay.length > 0 ? blockedByDay.map((d) => d.count) : [stats.active_blocked_ips || 0],
                backgroundColor: brandRed,
                borderRadius: 4,
                barThickness: 24,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { padding: 8, cornerRadius: 6 } },
            scales: {
              x: { grid: { display: false }, ticks: { font: { size: 11 } } },
              y: { beginAtZero: true, grid: { color: gridColor }, ticks: { precision: 0, font: { size: 11 } } },
            },
          },
        });
      }

      // 4. Detection Engine Breakdown
      const methodCanvas = document.getElementById("methodChart");
      if (methodCanvas) {
        const dist = analytics.decision_distribution || {};
        chartInstances.method = new Chart(methodCanvas, {
          type: "doughnut",
          data: {
            labels: ["Behavior Analysis ML", "URL Feature Risk Engine"],
            datasets: [
              {
                data: [dist.total || stats.total_alerts || 1, Math.max(1, stats.total_requests || 5)],
                backgroundColor: [brandBlue, brandTeal],
                borderWidth: 2,
                borderColor: "#ffffff",
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
              legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } },
            },
          },
        });
      }

      // 5. Top Active IPs
      const topIpsCanvas = document.getElementById("topIpsChart");
      if (topIpsCanvas) {
        const topIps = analytics.top_ips || [];
        chartInstances.topIps = new Chart(topIpsCanvas, {
          type: "bar",
          data: {
            labels: topIps.map((t) => t.ip),
            datasets: [
              {
                label: "Requests",
                data: topIps.map((t) => t.request_count),
                backgroundColor: brandBlue,
                borderRadius: 4,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: "y",
            plugins: { legend: { display: false }, tooltip: { padding: 8, cornerRadius: 6 } },
            scales: {
              x: { grid: { color: gridColor }, ticks: { font: { size: 11 } } },
              y: { grid: { display: false }, ticks: { font: { family: "JetBrains Mono", size: 11 } } },
            },
          },
        });
      }

      // 6. HTTP Status Distribution
      const statusCanvas = document.getElementById("statusChart");
      if (statusCanvas) {
        const statusDist = analytics.status_distribution || { 200: stats.total_requests || 10 };
        const statusLabels = Object.keys(statusDist);
        const statusColors = statusLabels.map((c) => {
          const code = Number(c);
          if (code >= 500) return brandRed;
          if (code >= 400) return "#f59e0b";
          if (code >= 300) return brandIndigo;
          return brandGreen;
        });

        chartInstances.status = new Chart(statusCanvas, {
          type: "bar",
          data: {
            labels: statusLabels.map((c) => `HTTP ${c}`),
            datasets: [
              {
                label: "Requests",
                data: statusLabels.map((c) => statusDist[c]),
                backgroundColor: statusColors,
                borderRadius: 4,
                barThickness: 24,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { padding: 8, cornerRadius: 6 } },
            scales: {
              x: { grid: { display: false }, ticks: { font: { size: 11 } } },
              y: { beginAtZero: true, grid: { color: gridColor }, ticks: { font: { size: 11 } } },
            },
          },
        });
      }

      // 7. Behavioral Assessments Table
      if (tbody) {
        const rows = alerts.map((a) => {
          const session = sessions.find((s) => s.session_id === a.session_id);
          const rScore = a.risk_score != null ? Math.round(a.risk_score) : (a.confidence != null ? Math.round(a.confidence * 100) : null);
          const sev = (a.severity || (rScore != null ? (rScore >= 80 ? "CRITICAL" : rScore >= 60 ? "HIGH" : rScore >= 30 ? "MEDIUM" : "LOW") : "INFO")).toUpperCase();

          return `
          <tr class="hover:bg-slate-50 transition-colors">
            <td class="py-3 px-5 font-mono text-xs font-semibold text-slate-800">${F.sessionIdShort(a.session_id)}</td>
            <td class="py-3 px-5 font-mono text-xs text-slate-800">${a.ip}</td>
            <td class="py-3 px-5 font-mono text-xs text-slate-600">${session ? F.number(session.request_count) : "—"}</td>
            <td class="py-3 px-5 font-mono text-xs text-slate-500">[28-dim behavioral vector]</td>
            <td class="py-3 px-5 whitespace-nowrap">${F.predictionBadge(a.prediction)}</td>
            <td class="py-3 px-5 whitespace-nowrap">${F.riskScoreBadge(rScore, sev)}</td>
          </tr>`;
        });

        tbody.innerHTML =
          rows.length > 0
            ? rows.join("")
            : `<tr><td colspan="6" class="py-8 text-center text-slate-500">No behavioral assessments recorded yet</td></tr>`;
      }
    } catch (err) {
      console.error("Analytics load failed:", err);
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-red-600">Failed to load analytics data from API</td></tr>`;
      }
    }
  }

  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      await load();
      SentinelUI.showToast("Analytics refreshed", "success");
    });
  }

  await load();
};
