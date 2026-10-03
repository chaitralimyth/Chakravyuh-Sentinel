window.SENTINEL_CONFIG = {
  // Production API URL - Deployed backend on Render
  // Frontend URL: https://chakravyuh-sentinel.netlify.app/
  // Backend URL: https://chakravyuh-sentinel.onrender.com
  API_BASE:
    localStorage.getItem("SENTINEL_API_BASE") ||
    (typeof window !== "undefined" &&
    (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
      ? "http://127.0.0.1:8000"
      : "https://chakravyuh-sentinel.onrender.com"),
};
