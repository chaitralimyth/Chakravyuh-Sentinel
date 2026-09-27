"""
Request logging + ML security evaluation middleware.

Flow:

Request
    ↓
Route executes
    ↓
Request is logged
    ↓
Session updated
    ↓
Every N requests:
    ↓
28 behaviour features
    ↓
Behaviour ML
    ↓
URL ML
    ↓
Risk Engine
    ↓
Security Agent
    ↓
Alert / Block
"""

import time
from datetime import datetime, timezone
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from app.database import SessionLocal
from app.db_models import RequestLog
from app.session_builder import (
    get_or_create_session,
    touch_session,
)
from app.config import SESSION_EVAL_THRESHOLD
from app.behavior_feature_extractor import (
    build_feature_vector,
)
from app.behavior_agent import (
    run_behavior_prediction,
)
from app.feature_extractor import (
    extract_features,
)
from app.model_loader import (
    predict_url,
)
from app.risk_engine import (
    calculate_risk,
    calculate_request_rate_score,
    calculate_auth_failure_score,
    calculate_endpoint_risk,
)
from app.agent import decide
from app.blocking_service import (
    block_ip,
)

class RequestLoggingMiddleware(
    BaseHTTPMiddleware
):

    async def dispatch(
        self,
        request,
        call_next,
    ):

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        request_timestamp = (
            datetime.now(timezone.utc)
        )

        start = time.perf_counter()
        # -----------------------------------------------------
        # Request metadata
        # -----------------------------------------------------

        content_length_header = (
            request.headers.get("content-length")
        )

        request_size = (
            int(content_length_header)
            if (
                content_length_header
                and content_length_header.isdigit()
            )
            else 0
        )

        query_string = (
            request.url.query or ""
        )

        query_length = len(query_string)

        # -----------------------------------------------------
        # Execute route
        # -----------------------------------------------------

        response = await call_next(
            request
        )

        response_time_ms = (
            time.perf_counter() - start
        ) * 1000

        # -----------------------------------------------------
        # Preserve response body
        # -----------------------------------------------------

        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        new_response = Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
            background=response.background,
        )

        db = SessionLocal()

        try:
            # -------------------------------------------------
            # Session
            # -------------------------------------------------
            session = get_or_create_session(
                db,
                client_ip,
            )
            # -------------------------------------------------
            # Log request
            # -------------------------------------------------

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
                query_data=query_string[:2000],
            )

            db.add(log)
            db.commit()

            # -------------------------------------------------
            # Update session
            # -------------------------------------------------

            session = touch_session(
                db,
                session,
            )

            # -------------------------------------------------
            # Behaviour evaluation threshold
            # -------------------------------------------------

            if (
                session.request_count > 0
                and session.request_count
                % SESSION_EVAL_THRESHOLD == 0
            ):

                rows = (
                    db.query(RequestLog)
                    .filter(
                        RequestLog.session_id
                        == session.session_id
                    )
                    .order_by(
                        RequestLog.timestamp.asc()
                    )
                    .all()
                )

                # =================================================
                # 1. BEHAVIOUR FEATURES
                # =================================================

                feature_vector = (
                    build_feature_vector(rows)
                )

                behavior_result = (
                    run_behavior_prediction(
                        feature_vector
                    )
                )

                behavior_attack_probability = (
                    behavior_result[
                        "attack_probability"
                    ]

                    if behavior_result[
                        "attack_probability"
                    ] is not None

                    else (
                        1.0
                        if behavior_result[
                            "prediction"
                        ] == "attacker"
                        else 0.0
                    )
                )

                # =================================================
                # 2. URL ML
                # =================================================

                current_url = str(
                    request.url
                )

                url_features = (
                    extract_features(
                        current_url
                    )
                )

                url_result = predict_url(
                    url_features
                )

                url_attack_probability = (
                    url_result[
                        "attack_probability"
                    ]
                )

                # =================================================
                # 3. Extract behavioural context
                # =================================================

                latest_features = {}

                # Reconstruct named features from
                # the vector using the same order.
                from app.behavior_model_loader import (
                    behavior_feature_order,
                )

                latest_features = dict(
                    zip(
                        behavior_feature_order,
                        feature_vector,
                    )
                )

                request_rate_score = (
                    calculate_request_rate_score(
                        latest_features.get(
                            "max_requests_per_second",
                            0,
                        )
                    )
                )

                auth_failure_score = (
                    calculate_auth_failure_score(
                        latest_features.get(
                            "auth_failure_ratio",
                            0,
                        )
                    )
                )

                endpoint_score = (
                    calculate_endpoint_risk(
                        request.url.path
                    )
                )

                # =================================================
                # 4. RISK ENGINE
                # =================================================

                risk_result = calculate_risk(
                    url_attack_probability=(
                        url_attack_probability
                    ),
                    behavior_attack_probability=(
                        behavior_attack_probability
                    ),
                    request_rate_score=(
                        request_rate_score
                    ),
                    auth_failure_score=(
                        auth_failure_score
                    ),
                    endpoint_risk_score=(
                        endpoint_score
                    ),
                )

                risk_score = (
                    risk_result["risk_score"]
                )

                severity = (
                    risk_result["severity"]
                )

                # =================================================
                # 5. FINAL SECURITY AGENT
                # =================================================

                action, reasons = decide(
                    risk_score=risk_score,
                    url=current_url,
                    behavior_prediction=(
                        behavior_result[
                            "prediction"
                        ]
                    ),
                    request_rate_score=(
                        request_rate_score
                    ),
                    auth_failure_score=(
                        auth_failure_score
                    ),
                )

                # -------------------------------------------------
                # Combine reasons
                # -------------------------------------------------

                reason_text = "; ".join(
                    reasons
                )

                # -------------------------------------------------
                # BLOCK
                # -------------------------------------------------

                if action == "BLOCK":

                    session.status = "blocked"

                    db.add(session)
                    db.commit()

                    block_ip(
                        db,
                        ip=client_ip,
                        reason=reason_text[:255],
                        prediction=(
                            behavior_result[
                                "prediction"
                            ]
                        ),
                        confidence=(
                            behavior_result[
                                "confidence"
                            ]
                        ),
                        session_id=(
                            session.session_id
                        ),
                        url_score=(
                            url_attack_probability
                        ),
                        behavior_score=(
                            behavior_attack_probability
                        ),
                        risk_score=risk_score,
                        severity=severity,
                    )

                # -------------------------------------------------
                # Non-blocking alert
                # -------------------------------------------------

                elif action in (
                    "ALERT",
                    "MONITOR",
                ):

                    from app.alert_service import (
                        create_alert,
                    )

                    create_alert(
                        db,
                        ip=client_ip,
                        action=action,
                        reason=reason_text[:255],
                        session_id=(
                            session.session_id
                        ),
                        prediction=(
                            behavior_result[
                                "prediction"
                            ]
                        ),
                        confidence=(
                            behavior_result[
                                "confidence"
                            ]
                        ),
                        url_score=(
                            url_attack_probability
                        ),
                        behavior_score=(
                            behavior_attack_probability
                        ),
                        risk_score=risk_score,
                        severity=severity,
                    )

        except Exception as exc:
            # -------------------------------------------------
            # Security pipeline should not silently destroy
            # the protected application.
            # -------------------------------------------------

            print(
                "[SENTINEL SECURITY PIPELINE ERROR]",
                repr(exc),
            )

        finally:
            db.close()
        return new_response