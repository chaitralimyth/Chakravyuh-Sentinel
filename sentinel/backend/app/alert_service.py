"""
Creates security alerts for the admin dashboard.
"""

from sqlalchemy.orm import Session as DBSession
from app.db_models import SecurityAlert
from app.incident_service import create_or_update_incident

def create_alert(
    db: DBSession,
    ip: str,
    action: str,
    reason: str,
    session_id: str | None = None,
    prediction: str | None = None,
    confidence: float | None = None,
    url_score: float | None = None,
    behavior_score: float | None = None,
    risk_score: float | None = None,
    severity: str | None = None,
) -> SecurityAlert:

    alert = SecurityAlert(
        session_id=session_id,
        ip=ip,
        prediction=prediction,
        confidence=confidence,
        url_score=url_score,
        behavior_score=behavior_score,
        risk_score=risk_score,
        severity=severity,
        action=action,
        reason=reason,
        is_read=False,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    create_or_update_incident(
        db=db,
        alert=alert
    )

    return alert