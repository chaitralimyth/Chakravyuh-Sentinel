import logging
from datetime import datetime, timezone
from typing import Optional, List, Union

from fastapi import FastAPI, Request, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

# Existing URL-risk pipeline
from app.feature_extractor import extract_features
from app.agent import decide
from app.model_loader import lr_model, rf_model, xgb_model, predict_url
from app.utils import track_ip

# Security / behavior / incident pipeline
from app.database import init_db, get_db
from app.security_middleware import IPBlockMiddleware
from app.blocking_service import is_ip_blocked, block_ip
from app.ip_service import get_client_ip
from app.sqli_detector import detect_sqli
from app.request_logging_middleware import RequestLoggingMiddleware
from app.rate_limit_middleware import RateLimitMiddleware, _rate_limiter
from app.dashboard_routes import router as dashboard_router
from app.config import ALLOWED_ORIGINS, CORS_ORIGINS, SESSION_EVAL_THRESHOLD, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
from app.db_models import RequestLog, SessionRecord, SecurityAlert, BlockedIP, SecurityIncident, RateLimitEvent
from app.session_builder import get_or_create_session, touch_session
from app.security_pipeline import evaluate_session_security
from app.incident_service import get_incident, close_incident, get_incidents
from app.explanation_service import generate_incident_explanation

app = FastAPI(title="Chakravyuh Sentinel API")
logger = logging.getLogger(__name__)

# Middleware: innermost first, CORS outermost (handles OPTIONS preflight)
# Order of execution: CORS -> IPBlockMiddleware -> RateLimitMiddleware -> RequestLoggingMiddleware
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(IPBlockMiddleware)

# Enable CORS for all external websites, supporting credentials and all HTTP methods/headers
if CORS_ORIGINS == "*" or "*" in ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

# Dashboard read-only routes
app.include_router(dashboard_router)


# Initialize database tables
init_db()


@app.on_event("startup")
def _init_security_db():
    init_db()



class URLPayload(BaseModel):
    url: str


class TrafficIngestRequest(BaseModel):
    """Request schema for external traffic ingestion from a protected website."""
    ip: str = Field(..., description="Client IP address")
    source_site: str = Field(default="x-beauty", min_length=1, max_length=100)
    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    endpoint: str = Field(..., description="URL path")
    status_code: int = Field(default=200, description="HTTP response status code")
    timestamp: datetime = Field(..., description="ISO-8601 timestamp")
    request_size: int = Field(default=0, description="Request size in bytes")
    response_size: int = Field(default=0, description="Response size in bytes")
    response_time_ms: float = Field(default=0.0, description="Response time in milliseconds")
    query_length: int = Field(default=0, description="Query string length")
    query_data: str = Field(default="", description="Query string data")
    website: Optional[str] = Field(default=None, description="Source website domain/identifier")


@app.get("/")
def home():
    return {"message": "Chakravyuh API running 🚀"}


def confidence_label(score: float):
    if score > 0.8:
        return "HIGH RISK"
    elif score > 0.4:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


@app.post("/analyze")
@app.post("/predict")
def analyze_url(payload: URLPayload, request: Request):
    """Processes URL risk evaluation for both frontend /analyze and /predict."""
    url = payload.url

    try:
        features = extract_features(url)

        lr_score = lr_model.predict_proba([features])[0][1]
        rf_score = rf_model.predict_proba([features])[0][1]
        xgb_score = xgb_model.predict_proba([features])[0][1]

        final_score = (lr_score + rf_score + xgb_score) / 3

        action, reasons = decide(final_score, url)

        client_ip = get_client_ip(request)
        request_count = track_ip(client_ip)

        if action == "BLOCK":
            risk = "HIGH RISK"
            db = SessionLocal()
            try:
                block_ip(
                    db=db,
                    ip=client_ip,
                    reason=reasons[0] if reasons else "High-risk URL threat blocked by Sentinel",
                    prediction="attacker",
                    confidence=float(final_score),
                    risk_score=95.0,
                    severity="CRITICAL",
                )
            except Exception as e:
                pass
            finally:
                db.close()
        elif action == "ALERT":
            risk = "MEDIUM RISK"
        else:
            risk = confidence_label(final_score)

        if request_count > 10:
            reasons.append("Too many requests from same user")
            action = "ALERT"
            risk = "MEDIUM RISK"

        return {
            "url": url,
            "score": float(final_score),
            "final_score": float(final_score),
            "risk_level": risk,
            "action": action,
            "reasons": reasons,
            "request_count": request_count,
            "model_confidence": {
                "logistic_regression": float(lr_score),
                "random_forest": float(rf_score),
                "xgboost": float(xgb_score),
            },
        }

    except Exception as e:
        return {"error": str(e), "score": 0.5}


@app.post("/predict-url")
def predict_url_endpoint(payload: URLPayload):
    """Inference endpoint for Random Forest URL threat classification."""
    try:
        features = extract_features(payload.url)
        result = predict_url(features)
        return {
            "url": payload.url,
            "prediction": result["prediction"],
            "prediction_value": result["prediction_value"],
            "attack_probability": result["attack_probability"],
            "confidence": result["confidence"],
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _process_traffic_item(db: Session, payload: TrafficIngestRequest) -> dict:
    """Helper to process a single traffic item into the Sentinel pipeline."""
    source_site = (payload.source_site or "x-beauty").strip().lower()
    if not source_site:
        raise HTTPException(status_code=422, detail="source_site must not be blank")

    # Parse timestamp safely
    if isinstance(payload.timestamp, datetime):
        request_timestamp = payload.timestamp
    elif payload.timestamp:
        try:
            request_timestamp = datetime.fromisoformat(str(payload.timestamp).replace('Z', '+00:00'))
        except Exception:
            request_timestamp = datetime.now(timezone.utc)
    else:
        request_timestamp = datetime.now(timezone.utc)

    if request_timestamp.tzinfo is None:
        request_timestamp = request_timestamp.replace(tzinfo=timezone.utc)

    # Immediate SQL injection detection on raw data before sanitization
    raw_query = payload.query_data or ""
    sqli_res = detect_sqli(raw_query)
    if not sqli_res["is_sqli"]:
        sqli_res = detect_sqli(payload.endpoint)

    # Sanitize query / body data to ensure passwords, tokens, and secrets are redacted
    from app.payload_sanitizer import sanitize_query_string, sanitize_json_text
    sanitized_data = raw_query
    if raw_query:
        trimmed = raw_query.strip()
        if trimmed.startswith("{") or trimmed.startswith("["):
            sanitized_data = sanitize_json_text(trimmed)
        else:
            sanitized_data = sanitize_query_string(trimmed)

    query_str = sanitized_data
    if payload.website and "site:" not in query_str:
        prefix = f"[site:{payload.website}] "
        query_str = f"{prefix}{query_str}".strip()

    # Get or create session for this IP and source_site
    session = get_or_create_session(db, payload.ip, source_site=source_site)

    # Create request log entry
    log = RequestLog(
        session_id=session.session_id,
        timestamp=request_timestamp,
        ip=payload.ip,
        source_site=source_site,
        method=payload.method,
        endpoint=payload.endpoint,
        status_code=payload.status_code,
        request_size=payload.request_size,
        response_size=payload.response_size,
        response_time_ms=payload.response_time_ms,
        query_length=payload.query_length or len(query_str),
        query_data=query_str[:2000],
    )
    db.add(log)
    db.commit()

    # Update session
    session = touch_session(db, session)

    # Check if client IP is currently blocked
    is_blocked = is_ip_blocked(db, payload.ip)
    action = "BLOCK" if is_blocked else "ALLOW"
    risk_score = None
    severity = None

    if sqli_res["is_sqli"]:
        action = "BLOCK"
        is_blocked = True
        risk_score = sqli_res["risk_score"]
        severity = "CRITICAL"
        reason = f"SQL injection attack payload detected: {sqli_res['matched_patterns'][0]}"
        block_ip(
            db=db,
            ip=payload.ip,
            reason=reason[:255],
            prediction="attacker",
            confidence=sqli_res["confidence"],
            session_id=session.session_id,
            risk_score=risk_score,
            severity=severity,
        )

    # Check rate limiter for this external IP (moderate-risk or standard)
    rate_info = {}
    if not is_blocked:
        is_mod = _rate_limiter.is_moderate_risk(payload.ip)
        rate_allowed, rate_info = _rate_limiter.is_allowed(payload.ip, is_moderate_risk=is_mod)
        if not rate_allowed or payload.status_code == 429:
            action = "RATE_LIMIT"
            try:
                rl_count = rate_info.get("current", 6) if rate_info else 6
                rl_win = rate_info.get("window", RATE_LIMIT_WINDOW_SECONDS) if rate_info else RATE_LIMIT_WINDOW_SECONDS
                rl_lim = rate_info.get("limit", RATE_LIMIT_REQUESTS) if rate_info else RATE_LIMIT_REQUESTS
                rl_burst = rate_info.get("burst_used", False) if rate_info else False
                violation = RateLimitEvent(
                    ip=payload.ip,
                    endpoint=payload.endpoint,
                    method=payload.method,
                    request_count=rl_count,
                    window_seconds=rl_win,
                    limit=rl_lim,
                    burst_used=rl_burst,
                )
                db.add(violation)
                db.commit()
            except Exception as rle_err:
                logger.error(f"Failed to persist ingested RateLimitEvent: {rle_err}")


    # Unified session evaluation if threshold reached
    if not is_blocked and session.request_count > 0 and session.request_count % SESSION_EVAL_THRESHOLD == 0:
        eval_res = evaluate_session_security(
            db=db,
            session=session,
            client_ip=payload.ip,
            current_url=payload.endpoint,
        )
        if eval_res and eval_res.get("evaluated"):
            eval_action = eval_res.get("action")
            risk_score = eval_res.get("risk_score")
            severity = eval_res.get("severity")
            is_blocked = is_ip_blocked(db, payload.ip)
            if eval_action == "BLOCK" or is_blocked:
                action = "BLOCK"
            elif not is_blocked and rate_info and not rate_allowed:
                action = "RATE_LIMIT"
            elif eval_action:
                action = eval_action

    return {
        "success": True,
        "message": "Traffic ingested successfully",
        "session_id": session.session_id,
        "request_count": session.request_count,
        "action": action,
        "blocked": is_blocked,
        "risk_score": risk_score,
        "severity": severity,
        "rate_limit_info": rate_info,
    }


@app.post("/api/logs")
@app.post("/api/ingest-traffic")
def ingest_traffic(payload: TrafficIngestRequest, db: Session = Depends(get_db)):
    """
    Ingest protected-site traffic into the unified Sentinel pipeline.
    Processing: RequestLog → Session Builder → Behavior ML + URL ML → Dynamic Risk Engine → Adaptive Agent
    """
    source_site = (payload.source_site or "x-beauty").strip().lower()
    try:
        return _process_traffic_item(db, payload)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("Traffic ingestion failed for source_site=%s", source_site)
        raise HTTPException(status_code=500, detail="Traffic ingestion failed") from exc


@app.post("/api/logs/batch")
@app.post("/api/ingest-traffic/batch")
def ingest_traffic_batch(payloads: List[TrafficIngestRequest]):
    """
    Ingest batches of external traffic requests from any website or reverse proxy.
    """
    db = SessionLocal()
    results = []
    try:
        for p in payloads:
            res = _process_traffic_item(db, p)
            results.append(res)
        return {
            "success": True,
            "ingested_count": len(results),
            "results": results,
        }
    except Exception as e:
        db.rollback()
        return {
            "success": False,
            "message": f"Failed to ingest traffic batch: {str(e)}",
        }
    finally:
        db.close()


@app.get("/api/check-ip/{ip}")
def check_ip_status(ip: str, db: Session = Depends(get_db)):
    """
    Check if an IP is currently blocked or rate-limited by Sentinel.
    Allows external applications like X Beauty to pre-check enforcement status.
    """
    blocked = is_ip_blocked(db, ip)
    if blocked:
        return {
            "ip": ip,
            "blocked": True,
            "rate_limited": False,
            "action": "BLOCK",
            "risk_score": 95.0,
            "rate_limit_info": {},
        }

    # Query active moderate risk from rate limiter or DB
    cached_risk = _rate_limiter.get_ip_risk(ip)
    if cached_risk is None:
        latest_alert = (
            db.query(SecurityAlert)
            .filter(SecurityAlert.ip == ip)
            .order_by(SecurityAlert.created_at.desc())
            .first()
        )
        if latest_alert and latest_alert.risk_score:
            cached_risk = latest_alert.risk_score
            _rate_limiter.set_ip_risk(ip, cached_risk)

    is_moderate = cached_risk is not None and (59.0 < cached_risk <= 79.0)
    rate_allowed, rate_info = _rate_limiter.check_allowed(ip, is_moderate_risk=is_moderate)
    action = "RATE_LIMIT" if not rate_allowed else ("MONITOR" if is_moderate else "ALLOW")
    return {
        "ip": ip,
        "blocked": False,
        "rate_limited": not rate_allowed,
        "action": action,
        "risk_score": cached_risk if cached_risk is not None else 0.0,
        "rate_limit_info": rate_info,
    }


class UnblockIPPayload(BaseModel):
    ip: str = Field(..., description="IP address to unblock")


@app.post("/api/unblock-ip")
def api_unblock_ip(payload: UnblockIPPayload, db: Session = Depends(get_db)):
    """
    Safely unblocks an IP address, deactivating active blocks in the database
    and resetting rate limiting risk scores. Enables fast test reset in demos.
    """
    blocks = (
        db.query(BlockedIP)
        .filter(BlockedIP.ip == payload.ip, BlockedIP.is_active.is_(True))
        .all()
    )
    for b in blocks:
        b.is_active = False
    db.commit()

    # Reset in-memory rate limiter risk and tracking history
    _rate_limiter.reset_ip(payload.ip)

    return {
        "success": True,
        "ip": payload.ip,
        "message": f"IP {payload.ip} unblocked successfully",
        "deactivated_blocks": len(blocks),
    }


# ============================================================
# ATTACK INVESTIGATION TIMELINE & INCIDENT ENDPOINTS
# ============================================================

@app.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    """
    List all sessions with security incidents, alerts, or active blocks.
    Compatible with Shrawan's investigation timeline UI.
    """
    sessions_with_alerts = (
        db.query(SessionRecord)
        .join(SecurityAlert, SessionRecord.session_id == SecurityAlert.session_id)
        .distinct()
        .order_by(SessionRecord.started_at.desc())
        .all()
    )

    blocked_sessions = (
        db.query(SessionRecord)
        .filter(SessionRecord.status == "blocked")
        .order_by(SessionRecord.started_at.desc())
        .all()
    )

    all_sessions = []
    seen_ids = set()

    for s in sessions_with_alerts + blocked_sessions:
        if s.session_id not in seen_ids:
            seen_ids.add(s.session_id)
            all_sessions.append(s)

    return [
        {
            "session_id": s.session_id,
            "ip": s.ip,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "last_activity": s.last_activity.isoformat() if s.last_activity else None,
            "status": s.status,
            "request_count": s.request_count,
            "duration_seconds": s.duration_seconds,
        }
        for s in all_sessions
    ]


@app.get("/incidents/{session_id}/timeline")
def get_incident_timeline(session_id: str, db: Session = Depends(get_db)):
    """
    Attack Investigation Timeline endpoint:
    Returns a chronological timeline of events for a given session.
    Combines data from request_logs, security_alerts, blocked_ips, and sessions.
    Also supports incident_id resolution if an integer is provided.
    """
    if detect_sqli(session_id)["is_sqli"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid session_id: SQL injection pattern detected",
        )

    actual_session_id = session_id
    if session_id.isdigit():
        inc = db.query(SecurityIncident).filter(SecurityIncident.id == int(session_id)).first()
        if inc and inc.session_id:
            actual_session_id = inc.session_id

    session = db.query(SessionRecord).filter(SessionRecord.session_id == actual_session_id).first()
    if not session:
        return {"error": "Session not found", "session_id": session_id}

    request_logs = (
        db.query(RequestLog)
        .filter(RequestLog.session_id == actual_session_id)
        .order_by(RequestLog.timestamp.asc())
        .all()
    )

    security_alerts = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.session_id == actual_session_id)
        .order_by(SecurityAlert.created_at.asc())
        .all()
    )

    blocked_ips = (
        db.query(BlockedIP)
        .filter(BlockedIP.ip == session.ip)
        .order_by(BlockedIP.blocked_at.asc())
        .all()
    )

    timeline_events = []

    # Session start event
    timeline_events.append({
        "timestamp": session.started_at.isoformat() if session.started_at else None,
        "event_type": "SESSION_START",
        "description": f"Session started for IP {session.ip}",
        "endpoint": None,
        "status": "active",
        "session_id": session.session_id,
        "severity": "info",
    })

    # Request log events
    for log in request_logs:
        endpoint_lower = (log.endpoint or "").lower()
        if log.status_code >= 400:
            event_type = "REQUEST_ERROR"
        elif "/admin" in endpoint_lower:
            event_type = "ADMIN_ACCESS"
        elif "/login" in endpoint_lower:
            event_type = "LOGIN_ATTEMPT"
        else:
            event_type = "REQUEST"

        timeline_events.append({
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "event_type": event_type,
            "description": f"{log.method} {log.endpoint}",
            "endpoint": log.endpoint,
            "status": str(log.status_code),
            "session_id": log.session_id,
            "severity": "info" if log.status_code < 400 else "warning",
        })

    # Security alert events
    for alert in security_alerts:
        timeline_events.append({
            "timestamp": alert.created_at.isoformat() if alert.created_at else None,
            "event_type": "SECURITY_ALERT",
            "description": f"Security alert: {alert.action} - {alert.reason}",
            "endpoint": None,
            "status": alert.action,
            "session_id": alert.session_id,
            "severity": "critical" if alert.action == "BLOCK" else "warning",
            "prediction": alert.prediction,
            "confidence": alert.confidence,
            "risk_score": alert.risk_score,
        })

    # Blocked IP events
    for block in blocked_ips:
        timeline_events.append({
            "timestamp": block.blocked_at.isoformat() if block.blocked_at else None,
            "event_type": "IP_BLOCKED",
            "description": f"IP blocked: {block.reason}",
            "endpoint": None,
            "status": "blocked",
            "session_id": actual_session_id,
            "severity": "critical",
            "prediction": block.prediction,
            "confidence": block.confidence,
            "blocked_until": block.blocked_until.isoformat() if block.blocked_until else None,
        })

    # Session end event
    if session.status in ["closed", "blocked"]:
        timeline_events.append({
            "timestamp": session.last_activity.isoformat() if session.last_activity else None,
            "event_type": "SESSION_END",
            "description": f"Session {session.status}",
            "endpoint": None,
            "status": session.status,
            "session_id": session.session_id,
            "severity": "info",
        })

    # Sort all events chronologically
    timeline_events.sort(key=lambda x: x["timestamp"] or "")

    return {
        "session_id": actual_session_id,
        "ip": session.ip,
        "session_status": session.status,
        "total_events": len(timeline_events),
        "timeline": timeline_events,
    }


@app.get("/incidents/{incident_id}/explanation")
def get_incident_explanation_endpoint(incident_id: int, db: Session = Depends(get_db)):
    """Incident explanation endpoint: returns human-readable factors for a security incident."""
    incident = get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.session_id == incident.session_id)
        .order_by(SecurityAlert.created_at.asc())
        .all()
    )
    explanation = generate_incident_explanation(incident, alerts)
    return {
        "incident_id": incident.id,
        "explanation": explanation,
    }


@app.patch("/incidents/{incident_id}/close")
def close_security_incident_endpoint(incident_id: int, db: Session = Depends(get_db)):
    """Close an open security incident."""
    incident = close_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "message": "Incident closed successfully",
        "incident_id": incident.id,
        "status": incident.status,
    }


# ============================================================
# EXTENDED DASHBOARD STATISTICS (Severity & Action Breakdown)
# ============================================================

@app.get("/stats/severity")
def get_severity_statistics(db: Session = Depends(get_db)):
    """Incident count broken down by severity tier."""
    rows = (
        db.query(SecurityIncident.severity, func.count(SecurityIncident.id))
        .group_by(SecurityIncident.severity)
        .all()
    )
    result = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for severity, count in rows:
        key = (severity or "LOW").upper()
        if key in result:
            result[key] = count
    return result


@app.get("/stats/actions")
def get_action_statistics(db: Session = Depends(get_db)):
    """Security alert count broken down by action policy."""
    rows = (
        db.query(SecurityAlert.action, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.action)
        .all()
    )
    result = {"ALLOW": 0, "MONITOR": 0, "RATE_LIMIT": 0, "BLOCK": 0}
    for action, count in rows:
        key = (action or "ALLOW").upper()
        if key in result:
            result[key] = count
    return result


# ============================================================
# RATE LIMITING ENDPOINTS
# ============================================================

@app.get("/rate-limit/stats")
def get_rate_limit_stats(
    db: Session = Depends(get_db),
    source_site: str = "x-beauty"
):
    """Get rate limiting statistics and recent violations."""
    source_site = source_site.strip().lower()
    total_violations = db.query(RateLimitEvent).count()
    
    # Query 429 status code logs from RequestLog
    rl_query = db.query(RequestLog).filter(RequestLog.status_code == 429)
    if source_site != "all":
        rl_query = rl_query.filter(RequestLog.source_site == source_site)
    total_429_requests = rl_query.count()

    # Get recent violations (last 100)
    recent_violations = (
        db.query(RateLimitEvent)
        .order_by(RateLimitEvent.created_at.desc())
        .limit(100)
        .all()
    )
    
    # Count violations by IP
    violations_by_ip = (
        db.query(RateLimitEvent.ip, func.count(RateLimitEvent.id))
        .group_by(RateLimitEvent.ip)
        .order_by(func.count(RateLimitEvent.id).desc())
        .limit(10)
        .all()
    )
    
    return {
        "total_violations": max(total_violations, total_429_requests),
        "total_429_requests": total_429_requests,
        "limit": RATE_LIMIT_REQUESTS,
        "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        "recent_violations": [
            {
                "id": v.id,
                "ip": v.ip,
                "endpoint": v.endpoint,
                "method": v.method,
                "request_count": v.request_count,
                "limit": v.limit,
                "window_seconds": v.window_seconds,
                "burst_used": v.burst_used,
                "reason": f"Exceeded {v.limit} requests per {v.window_seconds}s window",
                "action": "RATE_LIMIT",
                "status_code": 429,
                "created_at": v.created_at.isoformat() if v.created_at else None
            }
            for v in recent_violations
        ],
        "top_offenders": [
            {"ip": ip, "violation_count": count}
            for ip, count in violations_by_ip
        ]
    }


@app.get("/rate-limit/stats/{ip}")
def get_ip_rate_limit_stats(ip: str, db: Session = Depends(get_db)):
    """Get rate limit statistics for a specific IP."""
    violations = (
        db.query(RateLimitEvent)
        .filter(RateLimitEvent.ip == ip)
        .order_by(RateLimitEvent.created_at.desc())
        .limit(50)
        .all()
    )
    
    total_count = (
        db.query(RateLimitEvent)
        .filter(RateLimitEvent.ip == ip)
        .count()
    )
    
    return {
        "ip": ip,
        "total_violations": total_count,
        "recent_violations": [
            {
                "endpoint": v.endpoint,
                "method": v.method,
                "request_count": v.request_count,
                "limit": v.limit,
                "window_seconds": v.window_seconds,
                "burst_used": v.burst_used,
                "created_at": v.created_at.isoformat() if v.created_at else None
            }
            for v in violations
        ]
    }


# ============================================================
# PROTECTED APPLICATION ENDPOINTS (Search, Auth, Numeric)
# ============================================================

class LoginPayload(BaseModel):
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="User password")


@app.post("/api/auth/login")
@app.post("/api/login")
def api_login(payload: LoginPayload, request: Request, db: Session = Depends(get_db)):
    """
    Protected authentication endpoint with proactive SQL injection defense.
    Rejects injection payloads and blocks malicious client IPs before database execution.
    """
    client_ip = get_client_ip(request)

    for field_name, field_val in [("username", payload.username), ("password", payload.password)]:
        sqli = detect_sqli(field_val)
        if sqli["is_sqli"]:
            block_ip(
                db=db,
                ip=client_ip,
                reason=f"SQL injection attack payload in {field_name}: {sqli['matched_patterns'][0]}",
                prediction="attacker",
                confidence=sqli["confidence"],
                risk_score=sqli["risk_score"],
                severity="CRITICAL",
            )
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: SQL injection payload detected in {field_name}",
            )

    # Safe parameterized query: check if username exists in sessions
    # Parameterization guarantees unsafe SQL can never alter query structure
    session_row = db.query(SessionRecord).filter(SessionRecord.session_id == payload.username).first()

    return {
        "status": "success",
        "authenticated": False,
        "message": "Invalid credentials",
        "ip": client_ip,
    }


@app.get("/api/search")
def api_search(q: str = Query(..., min_length=1, max_length=500), request: Request = None, db: Session = Depends(get_db)):
    """
    Protected search endpoint.
    Differentiates benign queries from SQL injection attacks.
    Executes safely with strict parameterization.
    """
    client_ip = get_client_ip(request) if request else "unknown"

    sqli = detect_sqli(q)
    if sqli["is_sqli"]:
        block_ip(
            db=db,
            ip=client_ip,
            reason=f"SQL injection attack in search parameter: {sqli['matched_patterns'][0]}",
            prediction="attacker",
            confidence=sqli["confidence"],
            risk_score=sqli["risk_score"],
            severity="CRITICAL",
        )
        raise HTTPException(
            status_code=403,
            detail="Forbidden: SQL injection payload detected in search query",
        )

    # Safe parameterized query via SQLAlchemy ORM
    matches = (
        db.query(RequestLog)
        .filter(RequestLog.endpoint.contains(q))
        .limit(10)
        .all()
    )

    return {
        "query": q,
        "result_count": len(matches),
        "results": [{"id": m.id, "endpoint": m.endpoint} for m in matches],
    }


@app.get("/api/items/{item_id}")
def api_get_item(item_id: int, db: Session = Depends(get_db)):
    """
    Protected numeric identifier lookup.
    Enforces strict numeric type validation and parameterization.
    """
    item = db.query(RequestLog).filter(RequestLog.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    return {
        "id": item.id,
        "endpoint": item.endpoint,
        "status_code": item.status_code,
    }
