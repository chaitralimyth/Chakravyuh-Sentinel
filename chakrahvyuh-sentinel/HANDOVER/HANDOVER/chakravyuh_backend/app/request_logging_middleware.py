"""
Runs AFTER the existing route has executed (so the response is already
produced), then:
    1. logs the request/response into request_logs
    2. updates/creates the session (session_builder)
    3. if the session has hit a multiple of SESSION_EVAL_THRESHOLD requests,
       extracts the 28 behavior features, runs the model, runs the behavior
       agent, and blocks the IP if it decides BLOCK.

Does not perform blocking itself for unblocked IPs — that's IPBlockMiddleware,
which runs earlier in the stack and short-circuits before this ever executes
for a blocked IP. This middleware never returns 403 and never blocks.

Note: this reads and re-emits the response body to measure response_size.
That's safe for ordinary JSON/text responses (as in this project's existing
routes) but will buffer large streaming responses fully in memory — adjust
if you add file-streaming endpoints later.

request_size is read from the Content-Length header rather than by awaiting
request.body(), so the request body stream is never touched by this
middleware and downstream route handling (including POST body/form parsing)
is unaffected.
"""

import time
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.database import SessionLocal
from app.db_models import RequestLog
from app.session_builder import get_or_create_session, touch_session
from app.config import SESSION_EVAL_THRESHOLD
from app.behavior_feature_extractor import build_feature_vector
from app.behavior_agent import run_behavior_prediction
from app.blocking_service import block_ip


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        request_timestamp = datetime.now(timezone.utc)
        start = time.perf_counter()

        # Read request size from the Content-Length header instead of
        # consuming request.body(), so we never touch the request stream
        # and downstream route/body/form parsing is left completely intact.
        content_length_header = request.headers.get("content-length")
        request_size = int(content_length_header) if content_length_header and content_length_header.isdigit() else 0

        query_string = request.url.query or ""
        query_length = len(query_string)

        response = await call_next(request)

        response_time_ms = (time.perf_counter() - start) * 1000

        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        # Preserve the original response's background task (if any) so
        # anything the route scheduled via BackgroundTasks still runs.
        new_response = Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
            background=response.background,
        )

        db = SessionLocal()
        try:
            session = get_or_create_session(db, client_ip)

            log = RequestLog(
                session_id=session.session_id,
                timestamp=request_timestamp,
                ip=client_ip,
                method=request.method,
                endpoint=request.url.path,
                status_code=response.status_code,
                request_size=request_size,
                response_size=len(response_body),
                response_time_ms=response_time_ms,
                query_length=query_length,
                query_data=query_string[:2000],  # truncate to avoid unbounded storage
            )
            db.add(log)
            db.commit()

            session = touch_session(db, session)

            if session.request_count > 0 and session.request_count % SESSION_EVAL_THRESHOLD == 0:
                rows = (
                    db.query(RequestLog)
                    .filter(RequestLog.session_id == session.session_id)
                    .order_by(RequestLog.timestamp.asc())
                    .all()
                )
                feature_vector = build_feature_vector(rows)
                decision = run_behavior_prediction(feature_vector)

                if decision["action"] == "BLOCK":
                    session.status = "blocked"
                    db.add(session)
                    db.commit()

                    block_ip(
                        db,
                        ip=client_ip,
                        reason=decision["reason"],
                        prediction=decision["prediction"],
                        confidence=decision["confidence"],
                        session_id=session.session_id,
                    )
        finally:
            db.close()

        return new_response