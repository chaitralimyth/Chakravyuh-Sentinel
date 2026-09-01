document.addEventListener("DOMContentLoaded", () => {
  if (window.SentinelNav) {
    SentinelNav.init();
  }

  const page = document.body.dataset.page;
  if (page && window.SentinelPages && typeof SentinelPages[page] === "function") {
    SentinelPages[page]();
  }
});
