from typing import Optional
from sqlalchemy.orm import Session as DBSession

from app.db_models import SecurityAlert
from app.incident_service import create_or_update_incident


def create_alert(
    db: DBSession,
    ip: str,
    action: str,
    reason: str,
    session_id: Optional[str] = None,
    prediction: Optional[str] = None,
    confidence: Optional[float] = None,
    url_score: Optional[float] = None,
    behavior_score: Optional[float] = None,
    risk_score: Optional[float] = None,
    severity: Optional[str] = None,
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

    # Correlate alert into persistent incident
    try:
        create_or_update_incident(db, alert)
    except Exception as e:
        print("[SENTINEL INCIDENT CORRELATION WARNING]", repr(e))

    return alert
