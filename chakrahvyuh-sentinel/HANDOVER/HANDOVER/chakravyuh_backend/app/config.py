"""
Central environment/config loader for the security system.

Reads configuration from environment variables or a local .env file.

Database credentials are NEVER hardcoded.
"""

import os

from dotenv import load_dotenv


load_dotenv()


def _get_int(name: str, default: int) -> int:
    """Read an integer environment variable with a safe default."""

    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------
# Database
# ---------------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Default to local SQLite fallback for testing/development if DATABASE_URL is not set
    DATABASE_URL = "sqlite:///./chakravyuh_sentinel.db"



# ---------------------------------------------------------
# Session builder
# ---------------------------------------------------------

# Same IP + inactivity greater than this value
# creates a new session.

SESSION_TIMEOUT_MINUTES = _get_int(
    "SESSION_TIMEOUT_MINUTES",
    30,
)


# ---------------------------------------------------------
# Behavior evaluation
# ---------------------------------------------------------

# Run the behavior model whenever the session request count
# reaches a multiple of this value.

SESSION_EVAL_THRESHOLD = _get_int(
    "SESSION_EVAL_THRESHOLD",
    5,
)

if SESSION_EVAL_THRESHOLD <= 0:
    raise RuntimeError(
        "SESSION_EVAL_THRESHOLD must be greater than 0."
    )


# ---------------------------------------------------------
# Blocking
# ---------------------------------------------------------

# Duration of an IP block after the behavior agent
# returns BLOCK.

BLOCK_DURATION_MINUTES = _get_int(
    "BLOCK_DURATION_MINUTES",
    60,
)

if BLOCK_DURATION_MINUTES <= 0:
    raise RuntimeError(
        "BLOCK_DURATION_MINUTES must be greater than 0."
    )


# ---------------------------------------------------------
# CORS Configuration
# ---------------------------------------------------------

# Comma-separated list of allowed origins for CORS.
# Use "*" to accept all external websites, or specify comma-separated domains.
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

if CORS_ORIGINS == "*":
    # Accept requests from all origins (any website or client application)
    ALLOWED_ORIGINS = ["*"]
else:
    # Parse comma-separated origins
    ALLOWED_ORIGINS = [origin.strip() for origin in CORS_ORIGINS.split(",") if origin.strip()]
    if not any(origin.lower() == "https://singhaman.me" for origin in ALLOWED_ORIGINS):
        ALLOWED_ORIGINS.append("https://singhaman.me")


# ---------------------------------------------------------
# Adaptive Agent Risk Thresholds
# ---------------------------------------------------------

# Policy ranges (0 to 100):
#   0  to RISK_ALLOW_MAX             -> ALLOW (default: 0 to 29)
#   RISK_MONITOR_MIN to RISK_MONITOR_MAX  -> MONITOR (default: 30 to 59)
#   RISK_RATE_LIMIT_MIN to RISK_RATE_LIMIT_MAX -> RATE_LIMIT (default: 60 to 79)
#   RISK_BLOCK_MIN to 100            -> BLOCK (default: 80 to 100)

RISK_ALLOW_MAX = _get_int('RISK_ALLOW_MAX', 29)
RISK_MONITOR_MIN = _get_int('RISK_MONITOR_MIN', 30)
RISK_MONITOR_MAX = _get_int('RISK_MONITOR_MAX', 59)
RISK_RATE_LIMIT_MIN = _get_int('RISK_RATE_LIMIT_MIN', 60)
RISK_RATE_LIMIT_MAX = _get_int('RISK_RATE_LIMIT_MAX', 79)
RISK_BLOCK_MIN = _get_int('RISK_BLOCK_MIN', 80)


# ---------------------------------------------------------
# Rate Limiting Configuration
# ---------------------------------------------------------

# Rate limiting: maximum requests per time window per IP for normal traffic (default: 5 for local demo)
RATE_LIMIT_REQUESTS = _get_int('RATE_LIMIT_REQUESTS', 5)

# Rate limiting for moderate-risk clients (score 59-79): strict request quota
RATE_LIMIT_MODERATE_REQUESTS = _get_int('RATE_LIMIT_MODERATE_REQUESTS', 3)

# Time window in seconds for rate limiting
RATE_LIMIT_WINDOW_SECONDS = _get_int('RATE_LIMIT_WINDOW_SECONDS', 60)

# Rate limiting: burst capacity (allows short bursts above normal rate for low-risk traffic; default: 0 for strict demo enforcement)
RATE_LIMIT_BURST = _get_int('RATE_LIMIT_BURST', 0)

# Proxy configuration
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "true").lower() in ("true", "1", "yes")

# Paths exempt from rate limiting (health checks, docs, dashboard telemetry, external website ingestion, etc.)
RATE_LIMIT_EXEMPT_PATHS = {
    "/",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/stats",
    "/statistics",
    "/alerts",
    "/blocked-ips",
    "/sessions",
    "/incidents",
    "/requests",
    "/api/ingest-traffic",
    "/api/ingest-traffic/batch",
    "/api/logs",
    "/api/check-ip",
    "/api/unblock-ip",
}
