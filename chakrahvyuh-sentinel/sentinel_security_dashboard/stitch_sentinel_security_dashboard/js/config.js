window.SENTINEL_CONFIG = {
  // Production API URL - Update this after backend deployment
  // Frontend URL: https://chakravyuh-sentinel.netlify.app/
  // Backend URL will be: https://your-api.onrender.com (after Render deployment)
  API_BASE: localStorage.getItem("SENTINEL_API_BASE") || "http://127.0.0.1:8000",
};
