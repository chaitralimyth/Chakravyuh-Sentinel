window.SentinelPages = window.SentinelPages || {};

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function emptyRow(colspan, message) {
  return `<tr><td colspan="${colspan}" class="px-6 py-8 text-center text-on-surface-variant">${message}</td></tr>`;
}

function renderAlertRow(alert) {
  const F = window.SentinelFormat;
  const isAttacker = (alert.prediction || "").toLowerCase() === "attacker";
  return `
    <tr class="hover:bg-surface-bright/50 transition-colors h-12">
      <td class="px-6 py-3 font-data-mono text-data-mono">${alert.ip}</td>
      <td class="px-6 py-3">
        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full ${F.predictionClass(alert.prediction)} font-medium text-xs">
          <div class="w-1.5 h-1.5 rounded-full ${isAttacker ? "bg-error" : "bg-emerald-500"}"></div>
          ${F.predictionLabel(alert.prediction)}
        </span>
      </td>
      <td class="px-6 py-3">${F.percent(alert.confidence)}</td>
      <td class="px-6 py-3">
        <span class="px-2 py-1 ${F.actionClass(alert.action)} rounded font-medium text-xs tracking-wide">${(alert.action || "—").toUpperCase()}</span>
      </td>
      <td class="px-6 py-3 text-on-surface-variant text-sm truncate max-w-[200px]" title="${alert.reason || ""}">${F.truncate(alert.reason, 35)}</td>
      <td class="px-6 py-3 text-on-surface-variant">${F.time(alert.created_at)}</td>
      <td class="px-6 py-3 text-right">
        <span class="w-2 h-2 rounded-full ${alert.is_read ? "bg-outline-variant" : "bg-amber-500"} inline-block"></span>
      </td>
    </tr>`;
}

SentinelPages.dashboard = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("recent-alerts-body");
  const refreshBtn = document.getElementById("refresh-btn");

  async function load() {
    try {
      const [stats, alerts, analytics] = await Promise.all([
        SentinelAPI.getStats(),
        SentinelAPI.getAlerts({ limit: 5 }),
        SentinelAPI.getStatistics(),
      ]);

      setText("stat-total-requests", F.number(stats.total_requests));
      setText("stat-active-sessions", F.number(stats.active_sessions));
      setText("stat-total-alerts", F.number(stats.total_alerts));
      setText("stat-unread-alerts", `${F.number(stats.unread_alerts)} Unread`);
      setText("stat-blocked-ips", F.number(stats.active_blocked_ips));

      if (tbody) {
        tbody.innerHTML =
          alerts.length > 0
            ? alerts.map(renderAlertRow).join("")
            : emptyRow(7, "No security alerts yet");
      }

      const dist = analytics.decision_distribution || {};
      setText("decision-total", F.number(dist.total));
      setText("decision-normal-pct", `Normal (${dist.normal_pct ?? 0}%)`);
      setText("decision-attacker-pct", `Attacker (${dist.attacker_pct ?? 0}%)`);
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(7, "Unable to load alerts — is the API running?");
    }
  }

  if (refreshBtn) refreshBtn.addEventListener("click", load);
  await load();
};

SentinelPages.alerts = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("alerts-table-body");

  async function load() {
    try {
      const [stats, alerts] = await Promise.all([
        SentinelAPI.getStats(),
        SentinelAPI.getAlerts({ limit: 100 }),
      ]);

      setText("alert-stat-total", F.number(stats.total_alerts));
      setText("alert-stat-unread", F.number(stats.unread_alerts));
      setText("alert-stat-blocks", F.number(alerts.filter((a) => a.action === "BLOCK").length));
      setText(
        "alert-stat-attacker",
        F.number(alerts.filter((a) => (a.prediction || "").toLowerCase() === "attacker").length)
      );

      if (tbody) {
        tbody.innerHTML =
          alerts.length > 0
            ? alerts
                .map(
                  (a) => `
          <tr class="hover:bg-surface-container-low/50 transition-colors ${!a.is_read ? "bg-error-container/10" : ""}">
            <td class="px-4 py-3 font-data-mono text-data-mono">ALT-${a.id}</td>
            <td class="px-4 py-3 font-data-mono text-data-mono">${a.ip}</td>
            <td class="px-4 py-3">
              <span class="inline-flex items-center gap-1 ${F.predictionClass(a.prediction)} px-2 py-0.5 rounded font-medium text-xs">
                ${F.predictionLabel(a.prediction)}
              </span>
            </td>
            <td class="px-4 py-3">${F.percent(a.confidence)}</td>
            <td class="px-4 py-3">
              <span class="inline-flex items-center justify-center ${F.actionClass(a.action)} px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wider w-24">${(a.action || "—").toUpperCase()}</span>
            </td>
            <td class="px-4 py-3 text-on-surface-variant">${F.truncate(a.reason, 50)}</td>
            <td class="px-4 py-3 font-data-mono text-data-mono text-on-surface-variant">${F.datetime(a.created_at)}</td>
            <td class="px-4 py-3">
              <span class="inline-flex items-center gap-1 ${a.is_read ? "text-on-surface-variant" : "text-secondary font-medium"} text-xs">
                ${a.is_read ? "Read" : "Unread"}
              </span>
            </td>
          </tr>`
                )
                .join("")
            : emptyRow(8, "No alerts recorded");
      }
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(8, "Unable to load alerts");
    }
  }

  await load();
};

SentinelPages["blocked-ips"] = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("blocked-ips-body");
  const countLabel = document.getElementById("blocked-count-label");

  async function load() {
    try {
      const blocks = await SentinelAPI.getBlockedIps({ active_only: false, limit: 200 });
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
          active.filter((b) => new Date(b.blocked_until).getTime() <= sixHours).length
        )
      );

      if (countLabel) {
        countLabel.textContent = `Showing ${blocks.length} record${blocks.length === 1 ? "" : "s"}`;
      }

      if (tbody) {
        tbody.innerHTML =
          blocks.length > 0
            ? blocks
                .map((b) => {
                  const confPct = b.confidence != null ? Math.round(b.confidence * 100) : 0;
                  return `
          <tr class="border-b border-surface-container-highest hover:bg-surface-bright transition-colors h-[48px] group">
            <td class="px-4 py-3 font-data-mono text-data-mono text-on-surface font-medium">${b.ip}</td>
            <td class="px-4 py-3 text-on-surface">${F.predictionLabel(b.prediction)}</td>
            <td class="px-4 py-3">
              <div class="flex items-center gap-2">
                <div class="w-16 h-1.5 bg-surface-container-high rounded-full overflow-hidden">
                  <div class="h-full bg-error" style="width:${confPct}%"></div>
                </div>
                <span class="text-on-surface-variant font-data-mono text-data-mono">${confPct}%</span>
              </div>
            </td>
            <td class="px-4 py-3 text-on-surface-variant">BLOCK</td>
            <td class="px-4 py-3">
              <span class="inline-flex items-center px-2 py-0.5 rounded ${b.is_active ? "bg-error-container text-error" : "bg-surface-variant text-on-surface-variant"} text-[10px] font-bold tracking-wider uppercase">${b.is_active ? "Active" : "Expired"}</span>
            </td>
            <td class="px-4 py-3 text-on-surface-variant">${F.date(b.blocked_at)}</td>
            <td class="px-4 py-3 text-right"></td>
          </tr>`;
                })
                .join("")
            : emptyRow(7, "No blocked IPs");
      }
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(7, "Unable to load blocked IPs");
    }
  }

  await load();
};

SentinelPages.requests = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("requests-table-body");
  const footer = document.getElementById("requests-footer");

  async function load() {
    try {
      const logs = await SentinelAPI.getRequests({ limit: 100 });
      if (footer) footer.textContent = `Showing ${logs.length} most recent requests`;

      if (tbody) {
        tbody.innerHTML =
          logs.length > 0
            ? logs
                .map(
                  (r) => `
          <tr class="hover:bg-surface-bright transition-colors group cursor-pointer">
            <td class="py-3 px-4 text-on-surface-variant whitespace-nowrap">${F.datetime(r.timestamp)}</td>
            <td class="py-3 px-4 text-on-surface whitespace-nowrap">${r.ip}</td>
            <td class="py-3 px-4 whitespace-nowrap">
              <span class="inline-block px-2 py-0.5 rounded text-[11px] font-bold bg-secondary-container/20 text-on-secondary-fixed-variant">${r.method}</span>
            </td>
            <td class="py-3 px-4 text-on-surface truncate max-w-[300px]" title="${r.endpoint}">${r.endpoint}</td>
            <td class="py-3 px-4 whitespace-nowrap">
              <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md ${F.statusCodeClass(r.status_code)} font-bold">${r.status_code}</span>
            </td>
            <td class="py-3 px-4 text-on-surface whitespace-nowrap text-right">${Math.round(r.response_time_ms)}ms</td>
          </tr>`
                )
                .join("")
            : emptyRow(6, "No request logs yet");
      }
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(6, "Unable to load request logs");
    }
  }

  await load();
};

SentinelPages.sessions = async function () {
  const F = window.SentinelFormat;
  const tbody = document.getElementById("sessions-table-body");

  async function load() {
    try {
      const sessions = await SentinelAPI.getSessions({ limit: 100 });
      const active = sessions.filter((s) => s.status === "active").length;
      const closed = sessions.filter((s) => s.status === "closed").length;
      const blocked = sessions.filter((s) => s.status === "blocked").length;

      setText("session-stat-active", F.number(active));
      setText("session-stat-closed", F.number(closed));
      setText("session-stat-blocked", F.number(blocked));

      if (tbody) {
        tbody.innerHTML =
          sessions.length > 0
            ? sessions
                .map(
                  (s) => `
          <tr class="hover:bg-surface-bright transition-colors cursor-pointer group">
            <td class="py-3 px-4 font-data-mono text-data-mono">${F.sessionIdShort(s.session_id)}</td>
            <td class="py-3 px-4 font-data-mono text-data-mono ${s.status === "blocked" ? "text-error" : ""}">${s.ip}</td>
            <td class="py-3 px-4 text-right font-data-mono text-data-mono">${F.number(s.request_count)}</td>
            <td class="py-3 px-4 text-on-surface-variant">${F.time(s.started_at)}</td>
            <td class="py-3 px-4 text-on-surface-variant">${F.time(s.last_activity)}</td>
            <td class="py-3 px-4">
              <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold ${s.status === "active" ? "bg-secondary/10 text-secondary border border-secondary/20" : s.status === "blocked" ? "bg-error/10 text-error border border-error/20" : "bg-surface-variant/50 text-on-surface-variant border border-outline-variant/30"}">
                ${(s.status || "unknown").toUpperCase()}
              </span>
            </td>
          </tr>`
                )
                .join("")
            : emptyRow(6, "No sessions yet");
      }
    } catch (err) {
      console.error(err);
      if (tbody) tbody.innerHTML = emptyRow(6, "Unable to load sessions");
    }
  }

  await load();
};
