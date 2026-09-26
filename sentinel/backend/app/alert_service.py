"""
Records security events for the admin dashboard.
"""

from sqlalchemy.orm import Session as DBSession

from app.db_models import SecurityAlert


def create_alert(
    db: DBSession,
    ip: str,
    action: str,
    reason: str,
    session_id: str | None = None,
    prediction: str | None = None,
    confidence: float | None = None,
) -> SecurityAlert:
    alert = SecurityAlert(
        session_id=session_id,
        ip=ip,
        prediction=prediction,
        confidence=confidence,
        action=action,
        reason=reason,
        is_read=False,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
