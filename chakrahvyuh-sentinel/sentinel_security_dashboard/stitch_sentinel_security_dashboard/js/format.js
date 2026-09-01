window.SentinelFormat = {
  number(value) {
    return new Intl.NumberFormat().format(value ?? 0);
  },

  percent(value) {
    if (value == null) return "—";
    const pct = value <= 1 ? value * 100 : value;
    return `${pct.toFixed(1)}%`;
  },

  time(iso) {
    if (!iso) return "—";
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  },

  datetime(iso) {
    if (!iso) return "—";
    return new Date(iso).toLocaleString();
  },

  date(iso) {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  },

  predictionLabel(prediction) {
    const p = (prediction || "unknown").toLowerCase();
    if (p === "attacker") return "ATTACKER";
    if (p === "normal") return "NORMAL";
    return p.toUpperCase();
  },

  predictionClass(prediction) {
    return (prediction || "").toLowerCase() === "attacker"
      ? "text-error bg-error/10"
      : "text-emerald-600 bg-emerald-600/10";
  },

  actionClass(action) {
    return (action || "").toUpperCase() === "BLOCK"
      ? "bg-error text-on-error"
      : "bg-emerald-500 text-white";
  },

  statusCodeClass(code) {
    if (code >= 500) return "bg-error/10 text-error";
    if (code >= 400) return "bg-error/10 text-error";
    if (code >= 300) return "bg-tertiary-fixed-dim/20 text-on-tertiary-container";
    return "bg-tertiary-fixed-dim/20 text-on-tertiary-container";
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
