"""
Security middleware.
Responsibilities:
1. Extract and validate client IP via ip_service (resisting header spoofing).
2. Intercept active SQL injection attacks pre-routing, immediately committing IP block and dropping request with HTTP 403.
3. Reject requests from active blocked IPs with HTTP 403 before protected application routes execute.
4. Allow exempt dashboard/monitoring endpoints to remain accessible to callers.
"""

import os
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse

from app.database import SessionLocal
from app.blocking_service import is_ip_blocked, block_ip
from app.ip_service import get_client_ip
from app.sqli_detector import detect_sqli

logger = logging.getLogger(__name__)

# Dashboard, health, and status monitoring endpoints that remain reachable
_EXEMPT_PATHS = {
    "/",
    "/stats",
    "/statistics",
    "/alerts",
    "/blocked-ips",
    "/sessions",
    "/incidents",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/check-ip",
}

ALLOW_LOCALHOST_BYPASS = os.getenv("ALLOW_LOCALHOST_BYPASS", "true").lower() in ("true", "1")


class IPBlockMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Always allow CORS preflight requests
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        client_ip = get_client_ip(request)

        # -------------------------------------------------------------
        # 1. Pre-Route SQL Injection Attack Interception
        # -------------------------------------------------------------
        # Inspect query string and path for SQL injection attacks
        query_str = request.url.query or ""
        sqli_check = detect_sqli(query_str)
        if not sqli_check["is_sqli"] and path:
            sqli_check = detect_sqli(path)

        if sqli_check["is_sqli"]:
            # Commit active block for client_ip immediately
            primary_pattern = sqli_check["matched_patterns"][0] if sqli_check["matched_patterns"] else "SQLi signature"
            reason = f"SQL injection attack payload detected: {primary_pattern}"
            db = SessionLocal()
            try:
                block_ip(
                    db=db,
                    ip=client_ip,
                    reason=reason[:255],
                    prediction="attacker",
                    confidence=sqli_check["confidence"],
                    risk_score=sqli_check["risk_score"],
                    severity="CRITICAL",
                )
            except Exception as e:
                logger.error(f"Failed to record SQLi block for {client_ip}: {e}")
            finally:
                db.close()

            # Return HTTP 403 Forbidden without executing downstream route handlers
            return JSONResponse(
                {
                    "detail": "Forbidden: SQL injection payload detected and blocked by Sentinel",
                    "action": "BLOCK",
                    "ip": client_ip,
                    "risk_score": sqli_check["risk_score"],
                    "severity": "CRITICAL",
                    "matched_pattern": primary_pattern,
                },
                status_code=403,
            )

        # -------------------------------------------------------------
        # 2. Check Exempt Paths for Blocked IPs
        # -------------------------------------------------------------
        if path in _EXEMPT_PATHS or path.startswith(("/docs", "/incidents", "/api/check-ip")):
            return await call_next(request)

        # -------------------------------------------------------------
        # 3. Localhost Safeguard (if explicitly enabled)
        # -------------------------------------------------------------
        if ALLOW_LOCALHOST_BYPASS and client_ip in ["127.0.0.1", "localhost", "::1"]:
            return await call_next(request)

        # -------------------------------------------------------------
        # 4. Active IP Blocklist Pre-Route Drop
        # -------------------------------------------------------------
        db = SessionLocal()
        try:
            if is_ip_blocked(db, client_ip):
                return JSONResponse(
                    {
                        "detail": "Forbidden: IP blocked by Sentinel",
                        "action": "BLOCK",
                        "ip": client_ip,
                    },
                    status_code=403,
                )
        except Exception as e:
            logger.error(f"Error checking IP block status for {client_ip}: {e}")
            # Secure fail-safe: return 503 service unavailable without leaking DB internals
            return JSONResponse(
                {"detail": "Security verification temporarily unavailable"},
                status_code=503,
            )
        finally:
            db.close()

        return await call_next(request)
