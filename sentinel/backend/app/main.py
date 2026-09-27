from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

# ============================================================
# APP IMPORTS
# ============================================================

from app.feature_extractor import extract_features
from app.model_loader import predict_url

from app.database import (
    init_db,
    get_db,
)

from app.db_models import (
    SecurityAlert,
    SecurityIncident,
    RequestLog,
    SessionRecord,
    BlockedIP,
)

from app.incident_service import (
    get_incidents,
    get_incident,
    close_incident,
)

from app.explanation_service import (
    generate_incident_explanation,
)

from app.security_middleware import (
    IPBlockMiddleware,
)

from app.request_logging_middleware import (
    RequestLoggingMiddleware,
)

# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Chakravyuh Sentinel",
    description="ML-based Web Security Gateway",
    version="1.0.0",
)

# ============================================================
# DATABASE
# ============================================================

@app.on_event("startup")
def _init_security_db():
    init_db()

# ============================================================
# MIDDLEWARE
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
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "Chakravyuh Sentinel",
    }

# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "message": "Chakravyuh Sentinel API running 🚀"
    }

# ============================================================
# URL ML TEST ENDPOINT
# ============================================================

@app.post("/predict")
def predict_url_endpoint(
    url: str,
):
    try:
        features = extract_features(url)
        result = predict_url(features)
        attack_probability = result["attack_probability"]
        if attack_probability >= 0.80:
            risk_level = "HIGH RISK"

        elif attack_probability >= 0.40:
            risk_level = "MEDIUM RISK"

        else:
            risk_level = "LOW RISK"

        return {
            "url": url,
            "prediction": result["prediction"],
            "attack_probability": attack_probability,
            "confidence": result["confidence"],
            "risk_level": risk_level,
        }

    except Exception as exc:
        return {
            "error": str(exc)
        }

# ============================================================
# SECURITY ALERTS
# ============================================================

@app.get("/alerts")
def list_alerts(
    db: Session = Depends(get_db),
):

    alerts = (
        db.query(SecurityAlert)
        .order_by(
            SecurityAlert.created_at.desc()
        )
        .limit(100)
        .all()
    )

    return [
        {
            "id": alert.id,
            "session_id": alert.session_id,
            "ip": alert.ip,
            "prediction": alert.prediction,
            "confidence": alert.confidence,
            "url_score": alert.url_score,
            "behavior_score": alert.behavior_score,
            "risk_score": alert.risk_score,
            "severity": alert.severity,
            "action": alert.action,
            "reason": alert.reason,
            "created_at": (
                alert.created_at.isoformat()
                if alert.created_at
                else None
            ),

            "is_read": alert.is_read,
        }
        for alert in alerts
    ]

# ============================================================
# INCIDENTS
# ============================================================

@app.get("/incidents")
def get_security_incidents(
    limit: int = 100,
    db: Session = Depends(get_db),
):

    incidents = get_incidents(
        db=db,
        limit=min(limit, 500)
    )

    return {
        "count": len(incidents),
        "incidents": [
            {
                "id": incident.id,
                "incident_key": incident.incident_key,
                "session_id": incident.session_id,
                "ip": incident.ip,
                "status": incident.status,
                "severity": incident.severity,
                "primary_action": incident.primary_action,
                "risk_score": incident.risk_score,
                "event_count": incident.event_count,
                "summary": incident.summary,
                "first_seen": (
                    incident.first_seen.isoformat()
                    if incident.first_seen
                    else None
                ),

                "last_seen": (
                    incident.last_seen.isoformat()
                    if incident.last_seen
                    else None
                ),
            }
            for incident in incidents
        ]
    }

# ============================================================
# INCIDENT DETAILS
# ============================================================

@app.get("/incidents/{incident_id}")
def get_security_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):

    incident = get_incident(
        db,
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    alerts = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.session_id == incident.session_id
        )
        .order_by(
            SecurityAlert.created_at.asc()
        )
        .all()
    )

    return {

        "incident": {
            "id": incident.id,
            "incident_key": incident.incident_key,
            "session_id": incident.session_id,
            "ip": incident.ip,
            "status": incident.status,
            "severity": incident.severity,
            "primary_action": incident.primary_action,
            "risk_score": incident.risk_score,
            "event_count": incident.event_count,
            "summary": incident.summary,

            "first_seen": (
                incident.first_seen.isoformat()
                if incident.first_seen
                else None
            ),

            "last_seen": (
                incident.last_seen.isoformat()
                if incident.last_seen
                else None
            ),
        },

        "alerts": [
            {
                "id": alert.id,
                "prediction": alert.prediction,
                "confidence": alert.confidence,
                "url_score": alert.url_score,
                "behavior_score": alert.behavior_score,
                "risk_score": alert.risk_score,
                "severity": alert.severity,
                "action": alert.action,
                "reason": alert.reason,
                "created_at": (
                    alert.created_at.isoformat()
                    if alert.created_at
                    else None
                ),
            }
            for alert in alerts
        ]
    }

# ============================================================
# ATTACK TIMELINE
# ============================================================

@app.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: int,
    db: Session = Depends(get_db),
):

    incident = get_incident(
        db,
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    timeline = []

    # --------------------------------------------------------
    # REQUEST EVENTS
    # --------------------------------------------------------

    requests = (
        db.query(RequestLog)
        .filter(
            RequestLog.session_id == incident.session_id
        )
        .order_by(
            RequestLog.timestamp.asc()
        )
        .all()
    )

    for request in requests:
        timeline.append({
            "timestamp": request.timestamp,
            "event_type": "REQUEST",
            "event": "HTTP request",
            "method": request.method,
            "endpoint": request.endpoint,
            "status": request.status_code,
            "response_time": request.response_time_ms,
            "ip": request.ip,
        })

    # --------------------------------------------------------
    # SECURITY ALERT EVENTS
    # --------------------------------------------------------

    alerts = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.session_id == incident.session_id
        )
        .order_by(
            SecurityAlert.created_at.asc()
        )
        .all()
    )

    for alert in alerts:
        timeline.append({
            "timestamp": alert.created_at,
            "event_type": "SECURITY_ALERT",
            "event": "Security alert generated",
            "action": alert.action,
            "severity": alert.severity,
            "prediction": alert.prediction,
            "risk_score": alert.risk_score,
            "url_score": alert.url_score,
            "behavior_score": alert.behavior_score,
            "reason": alert.reason,
            "ip": alert.ip,
        })

    # --------------------------------------------------------
    # SORT TIMELINE
    # --------------------------------------------------------

    timeline.sort(
        key=lambda x: x["timestamp"]
    )

    # --------------------------------------------------------
    # CONVERT DATETIME TO STRING
    # --------------------------------------------------------

    for event in timeline:
        if event["timestamp"]:
            event["timestamp"] = (
                event["timestamp"].isoformat()
            )

    return {
        "incident_id": incident.id,
        "session_id": incident.session_id,
        "ip": incident.ip,
        "event_count": len(timeline),
        "timeline": timeline,
    }

# ============================================================
# INCIDENT EXPLANATION
# ============================================================

@app.get("/incidents/{incident_id}/explanation")
def get_incident_explanation(
    incident_id: int,
    db: Session = Depends(get_db),
):

    incident = get_incident(
        db,
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    alerts = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.session_id == incident.session_id
        )
        .order_by(
            SecurityAlert.created_at.asc()
        )
        .all()
    )

    explanation = generate_incident_explanation(
        incident,
        alerts
    )

    return {
        "incident_id": incident.id,
        "explanation": explanation,
    }

# ============================================================
# CLOSE INCIDENT
# ============================================================

@app.patch("/incidents/{incident_id}/close")
def close_security_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):

    incident = close_incident(
        db,
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return {
        "message": "Incident closed successfully",
        "incident_id": incident.id,
        "status": incident.status,
    }

# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
):

    total_requests = (
        db.query(
            func.count(RequestLog.id)
        )
        .scalar()
        or 0
    )

    total_alerts = (
        db.query(
            func.count(SecurityAlert.id)
        )
        .scalar()
        or 0
    )

    total_incidents = (
        db.query(
            func.count(SecurityIncident.id)
        )
        .scalar()
        or 0
    )

    active_blocks = (
        db.query(
            func.count(BlockedIP.id)
        )
        .filter(
            BlockedIP.is_active.is_(True)
        )
        .scalar()
        or 0
    )

    active_sessions = (
        db.query(
            func.count(SessionRecord.session_id)
        )
        .filter(
            SessionRecord.status == "active"
        )
        .scalar()
        or 0
    )

    blocked_alerts = (
        db.query(
            func.count(SecurityAlert.id)
        )
        .filter(
            SecurityAlert.action == "BLOCK"
        )
        .scalar()
        or 0
    )

    high_risk_alerts = (
        db.query(
            func.count(SecurityAlert.id)
        )
        .filter(
            SecurityAlert.risk_score >= 60
        )
        .scalar()
        or 0
    )

    return {
        "total_requests": total_requests,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "active_sessions": active_sessions,
        "active_blocks": active_blocks,
        "blocked_alerts": blocked_alerts,
        "high_risk_alerts": high_risk_alerts,
    }

# ============================================================
# INCIDENT SEVERITY STATISTICS
# ============================================================

@app.get("/stats/severity")
def get_severity_statistics(
    db: Session = Depends(get_db),
):

    rows = (
        db.query(
            SecurityIncident.severity,
            func.count(SecurityIncident.id)
        )
        .group_by(
            SecurityIncident.severity
        )
        .all()
    )

    result = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for severity, count in rows:
        if severity in result:
            result[severity] = count

    return result

# ============================================================
# ACTION STATISTICS
# ============================================================

@app.get("/stats/actions")
def get_action_statistics(
    db: Session = Depends(get_db),
):

    rows = (
        db.query(
            SecurityAlert.action,
            func.count(SecurityAlert.id)
        )
        .group_by(
            SecurityAlert.action
        )
        .all()
    )

    result = {
        "ALLOW": 0,
        "MONITOR": 0,
        "ALERT": 0,
        "BLOCK": 0,
    }

    for action, count in rows:
        if action in result:
            result[action] = count

    return result