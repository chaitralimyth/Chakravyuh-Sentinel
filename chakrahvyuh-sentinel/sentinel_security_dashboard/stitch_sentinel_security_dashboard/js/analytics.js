window.SentinelPages = window.SentinelPages || {};

SentinelPages.analytics = async function () {
  const F = window.SentinelFormat;

  try {
    const [stats, analytics, alerts, sessions] = await Promise.all([
      SentinelAPI.getStats(),
      SentinelAPI.getStatistics(),
      SentinelAPI.getAlerts({ limit: 10 }),
      SentinelAPI.getSessions({ limit: 10 }),
    ]);

    setText("analytics-total-requests", F.number(stats.total_requests));

    const gridColor = "#e0e3e5";
    const brandColors = {
      normal: "#e0e3e5",
      attack: "#ba1a1a",
      primary: "#0058be",
      accent1: "#0c9488",
      accent2: "#004395",
    };

    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.color = "#76777d";

    const requestsByDay = analytics.requests_by_day || [];
    new Chart(document.getElementById("requestsChart"), {
      type: "line",
      data: {
        labels: requestsByDay.map((d) => d.date),
        datasets: [
          {
            label: "Requests",
            data: requestsByDay.map((d) => d.count),
            borderColor: brandColors.primary,
            backgroundColor: "rgba(0, 88, 190, 0.05)",
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: gridColor, drawBorder: false } },
        },
      },
    });

    const dist = analytics.decision_distribution || {};
    new Chart(document.getElementById("trafficPieChart"), {
      type: "doughnut",
      data: {
        labels: ["Normal", "Attacker"],
        datasets: [
          {
            data: [dist.normal || 0, dist.attacker || 0],
            backgroundColor: [brandColors.normal, brandColors.attack],
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "70%",
        plugins: { legend: { display: false } },
      },
    });

    const blockedByDay = analytics.blocked_by_day || [];
    new Chart(document.getElementById("blockedIpsChart"), {
      type: "bar",
      data: {
        labels: blockedByDay.map((d) => d.date),
        datasets: [
          {
            label: "Blocked IPs",
            data: blockedByDay.map((d) => d.count),
            backgroundColor: brandColors.attack,
            borderRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: gridColor, drawBorder: false } },
        },
      },
    });

    new Chart(document.getElementById("methodChart"), {
      type: "doughnut",
      data: {
        labels: ["Behavior Model", "URL Pipeline"],
        datasets: [
          {
            data: [dist.total || 1, stats.total_requests || 0],
            backgroundColor: [brandColors.primary, brandColors.accent1],
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "right", labels: { boxWidth: 12 } } },
      },
    });

    const topIps = analytics.top_ips || [];
    new Chart(document.getElementById("topIpsChart"), {
      type: "bar",
      data: {
        labels: topIps.map((t) => t.ip),
        datasets: [
          {
            label: "Requests",
            data: topIps.map((t) => t.request_count),
            backgroundColor: brandColors.primary,
            borderRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: gridColor } },
          y: { grid: { display: false } },
        },
      },
    });

    const statusDist = analytics.status_distribution || {};
    const statusLabels = Object.keys(statusDist);
    new Chart(document.getElementById("statusChart"), {
      type: "bar",
      data: {
        labels: statusLabels.map((c) => `HTTP ${c}`),
        datasets: [
          {
            label: "Count",
            data: statusLabels.map((c) => statusDist[c]),
            backgroundColor: brandColors.primary,
            borderRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: gridColor } },
        },
      },
    });

    const tbody = document.getElementById("assessments-body");
    if (tbody) {
      const rows = alerts.slice(0, 8).map((a, i) => {
        const session = sessions.find((s) => s.session_id === a.session_id);
        return `
        <tr class="border-b border-surface-variant hover:bg-surface-bright transition-colors">
          <td class="py-3 px-6 data-font">${F.sessionIdShort(a.session_id)}</td>
          <td class="py-3 px-6">${session ? F.number(session.request_count) : "—"}</td>
          <td class="py-3 px-6 text-on-surface-variant data-font">[28-dim vector]</td>
          <td class="py-3 px-6"><span class="${F.predictionClass(a.prediction)} px-2 py-1 rounded text-xs font-semibold">${F.predictionLabel(a.prediction)}</span></td>
          <td class="py-3 px-6 font-medium">${F.percent(a.confidence)}</td>
        </tr>`;
      });
      tbody.innerHTML =
        rows.length > 0
          ? rows.join("")
          : `<tr><td colspan="5" class="py-8 text-center text-on-surface-variant">No behavioral assessments yet</td></tr>`;
    }
  } catch (err) {
    console.error("Analytics load failed:", err);
  }
};

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}
