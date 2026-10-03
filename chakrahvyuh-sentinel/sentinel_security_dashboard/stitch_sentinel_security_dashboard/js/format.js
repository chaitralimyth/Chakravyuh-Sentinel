window.SentinelFormat = {
  number(value) {
    if (value === null || value === undefined) return "—";
    return new Intl.NumberFormat().format(value);
  },

  percent(value) {
    if (value === null || value === undefined) return "—";
    const num = Number(value);
    const pct = num <= 1 && num > 0 ? num * 100 : num;
    return `${pct.toFixed(1)}%`;
  },

  time(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return "—";
    }
  },

  datetime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return "—";
    }
  },

  date(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
      });
    } catch {
      return "—";
    }
  },

  relativeTime(iso) {
    if (!iso) return "—";
    try {
      const now = Date.now();
      const past = new Date(iso).getTime();
      const diffSec = Math.floor((now - past) / 1000);
      if (diffSec < 60) return `${Math.max(1, diffSec)}s ago`;
      const diffMin = Math.floor(diffSec / 60);
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr}h ago`;
      const diffDays = Math.floor(diffHr / 24);
      return `${diffDays}d ago`;
    } catch {
      return "—";
    }
  },

  duration(seconds) {
    if (seconds === null || seconds === undefined) return "—";
    const sec = Math.round(Number(seconds));
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    const remSec = sec % 60;
    if (min < 60) return `${min}m ${remSec}s`;
    const hr = Math.floor(min / 60);
    const remMin = min % 60;
    return `${hr}h ${remMin}m`;
  },

  bytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  },

  predictionLabel(prediction) {
    const p = (prediction || "unknown").toLowerCase();
    if (p === "attacker") return "ATTACKER";
    if (p === "normal") return "NORMAL";
    return p.toUpperCase();
  },

  predictionBadge(prediction) {
    const isAttacker = (prediction || "").toLowerCase() === "attacker";
    return isAttacker
      ? `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
          <span class="w-1.5 h-1.5 rounded-full bg-red-600"></span>
          ATTACKER
         </span>`
      : `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
          NORMAL
         </span>`;
  },

  severityBadge(severity) {
    const s = (severity || "").toUpperCase();
    if (s === "CRITICAL") {
      return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wider uppercase bg-red-100 text-red-800 border border-red-300">
        <span class="w-1.5 h-1.5 rounded-full bg-red-600 animate-pulse"></span>
        CRITICAL
      </span>`;
    }
    if (s === "HIGH") {
      return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wider uppercase bg-orange-100 text-orange-800 border border-orange-300">
        HIGH
      </span>`;
    }
    if (s === "MEDIUM") {
      return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wider uppercase bg-amber-100 text-amber-800 border border-amber-300">
        MEDIUM
      </span>`;
    }
    if (s === "LOW") {
      return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wider uppercase bg-emerald-100 text-emerald-800 border border-emerald-300">
        LOW
      </span>`;
    }
    return `<span class="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 text-slate-600 border border-slate-200">—</span>`;
  },

  riskScoreBadge(score, severity) {
    if (score === null || score === undefined) {
      return `<span class="text-slate-400 font-mono text-xs">—</span>`;
    }
    const val = Number(score);
    let colorClass = "text-emerald-700 bg-emerald-50 border-emerald-200";
    let barColor = "bg-emerald-500";
    if (val >= 80 || (severity && severity.toUpperCase() === "CRITICAL")) {
      colorClass = "text-red-700 bg-red-50 border-red-200";
      barColor = "bg-red-600";
    } else if (val >= 60 || (severity && severity.toUpperCase() === "HIGH")) {
      colorClass = "text-orange-700 bg-orange-50 border-orange-200";
      barColor = "bg-orange-500";
    } else if (val >= 30 || (severity && severity.toUpperCase() === "MEDIUM")) {
      colorClass = "text-amber-700 bg-amber-50 border-amber-200";
      barColor = "bg-amber-500";
    }

    return `
      <div class="inline-flex items-center gap-2">
        <span class="inline-flex items-center px-2 py-0.5 rounded font-mono font-bold text-xs border ${colorClass}">
          ${val.toFixed(0)}<span class="text-[10px] opacity-70">/100</span>
        </span>
        <div class="w-12 h-1.5 bg-slate-200 rounded-full overflow-hidden hidden sm:block">
          <div class="h-full ${barColor}" style="width: ${Math.min(100, Math.max(0, val))}%"></div>
        </div>
      </div>
    `;
  },

  actionBadge(action) {
    const act = (action || "—").toUpperCase();
    if (act === "BLOCK") {
      return `<span class="inline-flex items-center justify-center px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-red-600 text-white shadow-xs">BLOCK</span>`;
    }
    if (act === "ALERT") {
      return `<span class="inline-flex items-center justify-center px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-amber-500 text-white">ALERT</span>`;
    }
    if (act === "MONITOR") {
      return `<span class="inline-flex items-center justify-center px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-blue-600 text-white">MONITOR</span>`;
    }
    if (act === "RATE_LIMIT") {
      return `<span class="inline-flex items-center justify-center px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-indigo-600 text-white">RATE LIMIT</span>`;
    }
    if (act === "ALLOW") {
      return `<span class="inline-flex items-center justify-center px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-emerald-600 text-white">ALLOW</span>`;
    }
    return `<span class="inline-flex items-center justify-center px-2.5 py-0.5 rounded text-xs font-medium uppercase bg-slate-100 text-slate-700">${act}</span>`;
  },

  statusCodeBadge(code) {
    const c = Number(code);
    if (c >= 500) {
      return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-red-50 text-red-700 border border-red-200">${c}</span>`;
    }
    if (c >= 400) {
      return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">${c}</span>`;
    }
    if (c >= 300) {
      return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">${c}</span>`;
    }
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">${c}</span>`;
  },

  methodBadge(method) {
    const m = (method || "").toUpperCase();
    let cls = "bg-slate-100 text-slate-700 border-slate-200";
    if (m === "GET") cls = "bg-blue-50 text-blue-700 border-blue-200";
    else if (m === "POST") cls = "bg-emerald-50 text-emerald-700 border-emerald-200";
    else if (m === "PUT") cls = "bg-amber-50 text-amber-700 border-amber-200";
    else if (m === "DELETE") cls = "bg-red-50 text-red-700 border-red-200";
    else if (m === "PATCH") cls = "bg-purple-50 text-purple-700 border-purple-200";
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${cls}">${m}</span>`;
  },

  sessionStatusBadge(status) {
    const s = (status || "").toLowerCase();
    if (s === "active") {
      return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> ACTIVE
      </span>`;
    }
    if (s === "blocked") {
      return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
        <span class="w-1.5 h-1.5 rounded-full bg-red-600"></span> BLOCKED
      </span>`;
    }
    return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">
      CLOSED
    </span>`;
  },

  truncate(text, max = 40) {
    if (!text) return "—";
    return text.length > max ? `${text.slice(0, max)}…` : text;
  },

  sessionIdShort(id) {
    if (!id) return "—";
    return id.length > 8 ? id.slice(0, 8) : id;
  },
};
