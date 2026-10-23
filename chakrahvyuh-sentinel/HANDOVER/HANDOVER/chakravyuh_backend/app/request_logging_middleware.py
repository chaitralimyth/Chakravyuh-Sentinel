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

import logging
from app.database import SessionLocal
from app.db_models import RequestLog
from app.session_builder import get_or_create_session, touch_session
from app.config import SESSION_EVAL_THRESHOLD
from app.security_pipeline import evaluate_session_security
from app.ip_service import get_client_ip

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_ip = get_client_ip(request)
        request_timestamp = datetime.now(timezone.utc)
        start = time.perf_counter()

        # Read request size from the Content-Length header instead of
        # consuming request.body(), so we never touch the request stream
        # and downstream route/body/form parsing is left completely intact.
        content_length_header = request.headers.get("content-length")
        request_size = int(content_length_header) if content_length_header and content_length_header.isdigit() else 0

        # Retrieve sanitized query/body evidence cached by upstream IPBlockMiddleware,
        # or sanitize the URL query string directly without consuming the request body.
        query_evidence = getattr(request.state, "query_evidence", None)
        if query_evidence is None:
            from app.payload_sanitizer import sanitize_query_string
            q_str = sanitize_query_string(request.url.query)
            query_evidence = f"query: {q_str}" if q_str else ""
        query_length = len(query_evidence)

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

        # Fail-Open Resilience: Database logging failure must NEVER crash the request
        try:
            db = SessionLocal()
            try:
                session = get_or_create_session(db, client_ip, source_site="sentinel")

                log = RequestLog(
                    session_id=session.session_id,
                    timestamp=request_timestamp,
                    ip=client_ip,
                    source_site="sentinel",
                    method=request.method,
                    endpoint=request.url.path,
                    status_code=response.status_code,
                    request_size=request_size,
                    response_size=len(response_body),
                    response_time_ms=response_time_ms,
                    query_length=query_length,
                    query_data=query_evidence[:2000],  # sanitized and truncated to avoid unbounded storage
                )
                db.add(log)
                db.commit()

                session = touch_session(db, session)

                if session.request_count > 0 and session.request_count % SESSION_EVAL_THRESHOLD == 0:
                    evaluate_session_security(
                        db=db,
                        session=session,
                        client_ip=client_ip,
                        current_url=request.url.path,
                    )
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Fail-open: request telemetry logging failed: {e}")

        return new_response
