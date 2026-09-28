"""
Security middleware. Sole responsibility: reject requests from blocked IPs
with HTTP 403. Does NOT run any ML prediction and does NOT decide who gets
blocked — that's the behavior agent's job (see behavior_agent.py, invoked
from request_logging_middleware.py after a response has been produced).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.database import SessionLocal
from app.blocking_service import is_ip_blocked


class IPBlockMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_ip = request.client.host if request.client else "unknown"

        # Skip blocking for localhost (needed for API testing and admin access)
        if client_ip in ["127.0.0.1", "localhost", "::1"]:
            return await call_next(request)

        db = SessionLocal()
        try:
            blocked = is_ip_blocked(db, client_ip)
        finally:
            db.close()

        if blocked:
            return JSONResponse(
                status_code=403,
                content={"detail": "Access blocked due to suspicious behavior."},
            )

        return await call_next(request)
