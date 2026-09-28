from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Existing URL-risk pipeline
from app.feature_extractor import extract_features
from app.agent import decide
from app.model_loader import lr_model, rf_model, xgb_model
from app.utils import track_ip

# Security / behavior pipeline
from app.database import init_db, get_db
from app.security_middleware import IPBlockMiddleware
from app.request_logging_middleware import RequestLoggingMiddleware
from app.db_models import SecurityAlert, RequestLog, BlockedIP, SessionRecord


app = FastAPI()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

@app.on_event("startup")
def _init_security_db():
    init_db()


# ============================================================
# MIDDLEWARE
# ============================================================
#
# Order matters.
#
# CORS
#   ↓
# IPBlockMiddleware
#   ↓
# RequestLoggingMiddleware
#   ↓
# Routes
#
# The last middleware added runs first / is outermost.
# ============================================================

app.add_middleware(
    RequestLoggingMiddleware
)

app.add_middleware(
    IPBlockMiddleware
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# SECURITY ALERTS
# ============================================================

@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    """
    Admin dashboard endpoint:
    Fetch the latest recorded security alerts.
    """

    alerts = (
        db.query(SecurityAlert)
        .order_by(SecurityAlert.created_at.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "id": a.id,
            "session_id": a.session_id,
            "ip": a.ip,
            "prediction": a.prediction,
            "confidence": a.confidence,
            "action": a.action,
            "reason": a.reason,
            "created_at": (
                a.created_at.isoformat()
                if a.created_at
                else None
            ),
            "is_read": a.is_read,
        }
        for a in alerts
    ]


@app.get("/incidents/{session_id}/timeline")
def get_incident_timeline(session_id: str, db: Session = Depends(get_db)):
    """
    Attack Investigation Timeline endpoint:
    Returns a chronological timeline of events for a given session.
    Combines data from request_logs, security_alerts, blocked_ips, and sessions.
    """
    
    # Get session information
    session = db.query(SessionRecord).filter(SessionRecord.session_id == session_id).first()
    if not session:
        return {"error": "Session not found"}
    
    # Get all request logs for this session
    request_logs = (
        db.query(RequestLog)
        .filter(RequestLog.session_id == session_id)
        .order_by(RequestLog.timestamp.asc())
        .all()
    )
    
    # Get security alerts for this session
    security_alerts = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.session_id == session_id)
        .order_by(SecurityAlert.created_at.asc())
        .all()
    )
    
    # Get blocked IP records for this session's IP
    blocked_ips = (
        db.query(BlockedIP)
        .filter(BlockedIP.ip == session.ip)
        .order_by(BlockedIP.blocked_at.asc())
        .all()
    )
    
    # Build timeline events
    timeline_events = []
    
    # Add session start event
    timeline_events.append({
        "timestamp": session.started_at.isoformat() if session.started_at else None,
        "event_type": "SESSION_START",
        "description": f"Session started for IP {session.ip}",
        "endpoint": None,
        "status": "active",
        "session_id": session.session_id,
        "severity": "info"
    })
    
    # Add request log events
    for log in request_logs:
        # Determine event type based on endpoint and status
        event_type = "REQUEST"
        if log.status_code >= 400:
            event_type = "REQUEST_ERROR"
        elif "/admin" in log.endpoint.lower():
            event_type = "ADMIN_ACCESS"
        elif "/login" in log.endpoint.lower():
            event_type = "LOGIN_ATTEMPT"
        
        timeline_events.append({
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "event_type": event_type,
            "description": f"{log.method} {log.endpoint}",
            "endpoint": log.endpoint,
            "status": str(log.status_code),
            "session_id": log.session_id,
            "severity": "info" if log.status_code < 400 else "warning"
        })
    
    # Add security alert events
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
            "confidence": alert.confidence
        })
    
    # Add blocked IP events
    for block in blocked_ips:
        timeline_events.append({
            "timestamp": block.blocked_at.isoformat() if block.blocked_at else None,
            "event_type": "IP_BLOCKED",
            "description": f"IP blocked: {block.reason}",
            "endpoint": None,
            "status": "blocked",
            "session_id": session_id,
            "severity": "critical",
            "prediction": block.prediction,
            "confidence": block.confidence,
            "blocked_until": block.blocked_until.isoformat() if block.blocked_until else None
        })
    
    # Add session end event if session is closed or blocked
    if session.status in ["closed", "blocked"]:
        timeline_events.append({
            "timestamp": session.last_activity.isoformat() if session.last_activity else None,
            "event_type": "SESSION_END",
            "description": f"Session {session.status}",
            "endpoint": None,
            "status": session.status,
            "session_id": session.session_id,
            "severity": "info"
        })
    
    # Sort all events by timestamp
    timeline_events.sort(key=lambda x: x["timestamp"] or "")
    
    return {
        "session_id": session_id,
        "ip": session.ip,
        "session_status": session.status,
        "total_events": len(timeline_events),
        "timeline": timeline_events
    }


@app.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    """
    List all sessions that have security alerts or suspicious activity.
    """
    
    # Get sessions with security alerts
    sessions_with_alerts = (
        db.query(SessionRecord)
        .join(SecurityAlert, SessionRecord.session_id == SecurityAlert.session_id)
        .distinct()
        .order_by(SessionRecord.started_at.desc())
        .all()
    )
    
    # Get blocked sessions
    blocked_sessions = (
        db.query(SessionRecord)
        .filter(SessionRecord.status == "blocked")
        .order_by(SessionRecord.started_at.desc())
        .all()
    )
    
    # Combine and deduplicate
    all_sessions = []
    seen_ids = set()
    
    for session in sessions_with_alerts + blocked_sessions:
        if session.session_id not in seen_ids:
            seen_ids.add(session.session_id)
            all_sessions.append(session)
    
    return [
        {
            "session_id": s.session_id,
            "ip": s.ip,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "last_activity": s.last_activity.isoformat() if s.last_activity else None,
            "status": s.status,
            "request_count": s.request_count,
            "duration_seconds": s.duration_seconds
        }
        for s in all_sessions
    ]


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "message": "Chakravyuh API running 🚀"
    }


# ============================================================
# URL RISK HELPERS
# ============================================================

def confidence_label(score: float):
    if score > 0.8:
        return "HIGH RISK"
    elif score > 0.4:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


# ============================================================
# URL PREDICTION
# ============================================================

@app.post("/predict")
def predict(url: str, request: Request):

    try:

        # ----------------------------------------------------
        # Step 1: Extract URL features
        # ----------------------------------------------------

        features = extract_features(url)


        # ----------------------------------------------------
        # Step 2: Get model confidences
        # ----------------------------------------------------

        lr_score = lr_model.predict_proba([features])[0][1]
        rf_score = rf_model.predict_proba([features])[0][1]
        xgb_score = xgb_model.predict_proba([features])[0][1]


        # ----------------------------------------------------
        # Step 3: Combine model scores
        # ----------------------------------------------------

        final_score = (
            lr_score +
            rf_score +
            xgb_score
        ) / 3


        # ----------------------------------------------------
        # Step 4: Agent decision
        # ----------------------------------------------------

        action, reasons = decide(
            final_score,
            url
        )


        # ----------------------------------------------------
        # Step 5: Align risk level with action
        # ----------------------------------------------------

        if action == "BLOCK":
            risk = "HIGH RISK"

        elif action == "ALERT":
            risk = "MEDIUM RISK"

        else:
            risk = confidence_label(final_score)


        # ----------------------------------------------------
        # Step 6: Track IP
        # ----------------------------------------------------

        client_ip = request.client.host
        request_count = track_ip(client_ip)


        # ----------------------------------------------------
        # Step 7: Request-rate rule
        # ----------------------------------------------------

        if request_count > 10:

            reasons.append(
                "Too many requests from same user"
            )

            action = "ALERT"
            risk = "MEDIUM RISK"


        # ----------------------------------------------------
        # Step 8: Return response
        # ----------------------------------------------------

        return {
            "url": url,

            "model_confidence": {
                "logistic_regression": float(lr_score),
                "random_forest": float(rf_score),
                "xgboost": float(xgb_score)
            },

            "final_score": float(final_score),

            "risk_level": risk,

            "action": action,

            "reasons": reasons,

            "request_count": request_count
        }


    except Exception as e:

        return {
            "error": str(e)
        }