"""
Groups raw requests into sessions.

Rule: same IP + inactivity gap > SESSION_TIMEOUT_MINUTES => close the old
session (if any) and start a new one.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session as DBSession

from app.db_models import SessionRecord
from app.config import SESSION_TIMEOUT_MINUTES


def get_or_create_session(db: DBSession, ip: str) -> SessionRecord:
    now = datetime.now(timezone.utc)

    active_session = (
        db.query(SessionRecord)
        .filter(SessionRecord.ip == ip, SessionRecord.status == "active")
        .order_by(SessionRecord.last_activity.desc())
        .first()
    )

    if active_session is not None:
        last_activity = active_session.last_activity
        if last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)

        if now - last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            active_session.status = "closed"
            db.add(active_session)
            db.commit()
            active_session = None

    if active_session is None:
        active_session = SessionRecord(
            ip=ip,
            started_at=now,
            last_activity=now,
            duration_seconds=0.0,
            status="active",
            request_count=0,
        )
        db.add(active_session)
        db.commit()
        db.refresh(active_session)

    return active_session


def touch_session(db: DBSession, session: SessionRecord) -> SessionRecord:
    """Call after logging a new request against this session."""
    now = datetime.now(timezone.utc)

    started_at = session.started_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)

    session.last_activity = now
    session.request_count += 1
    session.duration_seconds = (now - started_at).total_seconds()

    db.add(session)
    db.commit()
    db.refresh(session)
    return session
