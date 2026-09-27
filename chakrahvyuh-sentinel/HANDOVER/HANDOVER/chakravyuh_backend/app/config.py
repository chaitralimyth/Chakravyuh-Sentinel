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
    raise RuntimeError(
        "DATABASE_URL environment variable is not configured. "
        "Set DATABASE_URL in your .env file before starting the application."
    )


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
# Use "*" for development (unrestricted), or specific domains for production.
# Example: "https://your-frontend.netlify.app,https://your-domain.com"
# For local development: "http://localhost:3000,http://127.0.0.1:5500"

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

if CORS_ORIGINS == "*":
    # Development mode: allow all origins
    ALLOWED_ORIGINS = ["*"]
else:
    # Production mode: parse comma-separated origins
    ALLOWED_ORIGINS = [origin.strip() for origin in CORS_ORIGINS.split(",") if origin.strip()]
    # Always ensure singhaman.me is included for the integration
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
