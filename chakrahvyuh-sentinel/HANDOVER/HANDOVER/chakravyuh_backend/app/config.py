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