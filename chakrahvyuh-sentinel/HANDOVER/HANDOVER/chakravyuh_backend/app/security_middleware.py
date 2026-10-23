"""
Security middleware.
Responsibilities:
1. Extract and validate client IP via ip_service (resisting header spoofing).
2. Safely buffer request stream so downstream handlers and body parsers receive an intact stream.
3. Intercept active SQL injection attacks pre-routing, immediately committing IP block and dropping request with HTTP 403.
4. Reject requests from active blocked IPs with HTTP 403 before protected application routes execute.
5. Allow exempt dashboard/monitoring endpoints to remain accessible to callers.
"""

import os
import json
import logging
from datetime import datetime, timezone
from fastapi import Request
from fastapi.responses import JSONResponse

from app.database import SessionLocal
from app.blocking_service import is_ip_blocked, block_ip
from app.ip_service import get_client_ip
from app.sqli_detector import detect_sqli, inspect_payload_for_sqli
from app.payload_sanitizer import build_evidence_string, redact_sensitive_data
from app.session_builder import get_or_create_session, touch_session
from app.db_models import RequestLog

logger = logging.getLogger(__name__)

# Dashboard, health, and status monitoring endpoints that remain reachable
_EXEMPT_PATHS = {
    "/",
    "/health",
    "/stats",
    "/statistics",
    "/alerts",
    "/blocked-ips",
    "/sessions",
    "/incidents",
    "/requests",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/check-ip",
    "/api/unblock-ip",
}

ALLOW_LOCALHOST_BYPASS = os.getenv("ALLOW_LOCALHOST_BYPASS", "false").lower() in ("true", "1")


class IPBlockMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Always allow CORS preflight requests
        if scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return

        # -------------------------------------------------------------
        # Buffer incoming request body so it can be inspected without
        # consuming or exhausting the stream for downstream handlers.
        # -------------------------------------------------------------
        messages = []
        body_bytes = b""
        more_body = True
        # Bound stream buffer to 2MB to prevent memory exhaustion
        while more_body and len(body_bytes) < 2 * 1024 * 1024:
            msg = await receive()
            messages.append(msg)
            body_bytes += msg.get("body", b"")
            more_body = msg.get("more_body", False)

        msg_idx = 0

        async def replay_receive():
            nonlocal msg_idx
            if msg_idx < len(messages):
                m = messages[msg_idx]
                msg_idx += 1
                return m
            return await receive()

        request = Request(scope, receive=replay_receive)
        path = request.url.path
        client_ip = get_client_ip(request)
        query_str = request.url.query or ""

        # -------------------------------------------------------------
        # 1. Pre-Route SQL Injection Attack Interception
        # -------------------------------------------------------------
        sqli_check = detect_sqli(query_str)
        if not sqli_check["is_sqli"] and path:
            sqli_check = detect_sqli(path)

        body_data = None
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type and body_bytes:
            try:
                body_data = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                if not sqli_check["is_sqli"]:
                    sqli_check = inspect_payload_for_sqli(body_data)
            except Exception:
                pass

        # Build sanitized evidence string for investigation
        primary_pattern = sqli_check["matched_patterns"][0] if sqli_check.get("matched_patterns") else None
        evidence = build_evidence_string(
            query_string=query_str,
            body_data=body_data,
            matched_pattern=primary_pattern,
        )

        # Store in scope state for downstream RequestLoggingMiddleware to reuse without re-parsing
        state = scope.setdefault("state", {})
        state["query_evidence"] = evidence
        state["query_length"] = len(evidence)

        if sqli_check["is_sqli"]:
            reason = f"SQL injection attack payload detected: {primary_pattern or 'SQLi signature'}"

            db = SessionLocal()
            try:
                session = get_or_create_session(db, client_ip, source_site="sentinel")

                # Record the blocked request into request_logs with status 403 and sanitized evidence
                cl_header = request.headers.get("content-length", "0")
                req_size = int(cl_header) if cl_header and cl_header.isdigit() else len(body_bytes)
                log = RequestLog(
                    session_id=session.session_id,
                    timestamp=datetime.now(timezone.utc),
                    ip=client_ip,
                    source_site="sentinel",
                    method=request.method,
                    endpoint=path,
                    status_code=403,
                    request_size=req_size,
                    response_size=150,
                    response_time_ms=0.0,
                    query_length=len(evidence),
                    query_data=evidence[:2000],
                )
                db.add(log)
                session = touch_session(db, session)

                # Commit active block for client_ip immediately
                block_ip(
                    db=db,
                    ip=client_ip,
                    reason=reason[:255],
                    prediction="attacker",
                    confidence=sqli_check["confidence"],
                    session_id=session.session_id,
                    risk_score=sqli_check["risk_score"],
                    severity="CRITICAL",
                )
            except Exception as e:
                logger.error(f"Failed to record SQLi block for {client_ip}: {e}")
            finally:
                db.close()

            # Return HTTP 403 Forbidden without executing downstream route handlers
            resp = JSONResponse(
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
            await resp(scope, replay_receive, send)
            return

        # -------------------------------------------------------------
        # 2. Check Exempt Paths for Blocked IPs
        # -------------------------------------------------------------
        if (
            path in _EXEMPT_PATHS
            or path.startswith(("/docs", "/incidents", "/api/check-ip", "/blocked-ips", "/alerts"))
        ):
            await self.app(scope, replay_receive, send)
            return

        # -------------------------------------------------------------
        # 3. Active IP Blocklist Pre-Route Drop
        # -------------------------------------------------------------
        db = SessionLocal()
        try:
            if is_ip_blocked(db, client_ip):
                # Also log dropped request telemetry for investigation
                try:
                    sess = get_or_create_session(db, client_ip, source_site="sentinel")
                    drop_log = RequestLog(
                        session_id=sess.session_id,
                        timestamp=datetime.now(timezone.utc),
                        ip=client_ip,
                        source_site="sentinel",
                        method=request.method,
                        endpoint=path,
                        status_code=403,
                        request_size=len(body_bytes),
                        response_size=80,
                        response_time_ms=0.0,
                        query_length=len(evidence),
                        query_data=evidence[:2000],
                    )
                    db.add(drop_log)
                    db.commit()
                except Exception as log_err:
                    logger.debug(f"Failed to log dropped request for blocked IP: {log_err}")

                resp = JSONResponse(
                    {
                        "detail": "Forbidden: IP blocked by Sentinel",
                        "action": "BLOCK",
                        "ip": client_ip,
                    },
                    status_code=403,
                )
                await resp(scope, replay_receive, send)
                return
        except Exception as e:
            logger.error(f"Error checking IP block status for {client_ip}: {e}")
            resp = JSONResponse(
                {"detail": "Security verification temporarily unavailable"},
                status_code=503,
            )
            await resp(scope, replay_receive, send)
            return
        finally:
            db.close()

        # -------------------------------------------------------------
        # 4. Localhost Safeguard (for unblocked dev traffic)
        # -------------------------------------------------------------
        if ALLOW_LOCALHOST_BYPASS and client_ip in ["127.0.0.1", "localhost", "::1"]:
            await self.app(scope, replay_receive, send)
            return

        await self.app(scope, replay_receive, send)
