from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db_models import SecurityIncident, SecurityAlert

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

ACTION_RANK = {
    "ALLOW": 0,
    "MONITOR": 1,
    "ALERT": 2,
    "BLOCK": 3
}

def get_incident_key(session_id: str | None, ip: str) -> str:
    """
    Creates a stable correlation key.

    Primary correlation is based on session.
    If no session exists, IP is used.
    """

    if session_id:
        return f"SESSION:{session_id}"

    return f"IP:{ip}"

def _higher_severity(current: str, new: str) -> str:
    current_rank = SEVERITY_RANK.get(current, 0)
    new_rank = SEVERITY_RANK.get(new, 0)
    return new if new_rank > current_rank else current

def _higher_action(current: str, new: str) -> str:
    current_rank = ACTION_RANK.get(current, 0)
    new_rank = ACTION_RANK.get(new, 0)
    return new if new_rank > current_rank else current

def create_or_update_incident(
    db: Session,
    alert: SecurityAlert
):
    """
    Creates a new incident or updates an existing incident
    using the session/IP as the correlation key.
    """

    incident_key = get_incident_key(
        alert.session_id,
        alert.ip
    )

    incident = (
        db.query(SecurityIncident)
        .filter(
            SecurityIncident.incident_key == incident_key
        )
        .first()
    )

    now = datetime.now(timezone.utc)
    if incident is None:
        incident = SecurityIncident(
            incident_key=incident_key,
            session_id=alert.session_id,
            ip=alert.ip,
            status="OPEN",
            severity=alert.severity or "LOW",
            primary_action=alert.action or "MONITOR",
            risk_score=alert.risk_score or 0.0,
            event_count=1,
            summary=alert.reason,
            first_seen=alert.created_at or now,
            last_seen=alert.created_at or now,
            created_at=now,
            updated_at=now
        )

        db.add(incident)

    else:
        incident.event_count += 1
        incident.severity = _higher_severity(
            incident.severity,
            alert.severity or "LOW"
        )
        incident.primary_action = _higher_action(
            incident.primary_action,
            alert.action or "MONITOR"
        )
        incident.risk_score = max(
            incident.risk_score or 0.0,
            alert.risk_score or 0.0
        )
        incident.last_seen = alert.created_at or now
        incident.updated_at = now

        # Keep the latest important reason
        if alert.reason:
            incident.summary = alert.reason

    db.commit()
    db.refresh(incident)
    return incident

def get_incident(
    db: Session,
    incident_id: int
):
    return (
        db.query(SecurityIncident)
        .filter(SecurityIncident.id == incident_id)
        .first()
    )

def get_incidents(
    db: Session,
    limit: int = 100
):
    return (
        db.query(SecurityIncident)
        .order_by(SecurityIncident.last_seen.desc())
        .limit(limit)
        .all()
    )

def close_incident(
    db: Session,
    incident_id: int
):
    incident = get_incident(db, incident_id)
    if incident is None:
        return None

    incident.status = "CLOSED"
    incident.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(incident)
    return incident