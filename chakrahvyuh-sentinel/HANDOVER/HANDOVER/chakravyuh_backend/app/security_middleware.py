"""
Security middleware. Sole responsibility: reject requests from blocked IPs
with HTTP 403. Does NOT run any ML prediction and does NOT decide who gets
blocked — that's the behavior agent's job (see behavior_agent.py, invoked
from request_logging_middleware.py after a response has been produced).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse

from app.database import SessionLocal
from app.blocking_service import is_ip_blocked

# Dashboard and health endpoints must remain reachable even when the caller IP is blocked.
_EXEMPT_PATHS = {
    "/",
    "/stats",
    "/statistics",
    "/alerts",
    "/blocked-ips",
    "/requests",
    "/sessions",
    "/docs",
    "/redoc",
    "/openapi.json",
}


class IPBlockMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _EXEMPT_PATHS or path.startswith("/docs"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        db = SessionLocal()
        try:
            if is_ip_blocked(db, client_ip):
                return JSONResponse(
                    {"detail": "Forbidden: IP blocked by Sentinel"},
                    status_code=403,
                )
        finally:
            db.close()

        return await call_next(request)
