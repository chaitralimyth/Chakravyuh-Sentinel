"""
Manages active IP blocks.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session as DBSession

from app.db_models import BlockedIP
from app.config import BLOCK_DURATION_MINUTES
from app.alert_service import create_alert


def is_ip_blocked(
    db: DBSession,
    ip: str,
) -> bool:

    now = datetime.now(timezone.utc)

    active_blocks = (
        db.query(BlockedIP)
        .filter(
            BlockedIP.ip == ip,
            BlockedIP.is_active.is_(True),
        )
        .all()
    )

    still_blocked = False

    for block in active_blocks:

        blocked_until = block.blocked_until

        if blocked_until.tzinfo is None:

            blocked_until = blocked_until.replace(
                tzinfo=timezone.utc
            )

        if blocked_until <= now:

            block.is_active = False
            db.add(block)

        else:

            still_blocked = True

    if active_blocks:
        db.commit()

    return still_blocked


def block_ip(
    db: DBSession,
    ip: str,
    reason: str,
    prediction: str | None = None,
    confidence: float | None = None,
    session_id: str | None = None,
    url_score: float | None = None,
    behavior_score: float | None = None,
    risk_score: float | None = None,
    severity: str | None = None,
) -> BlockedIP:

    now = datetime.now(timezone.utc)

    blocked_until = (
        now
        + timedelta(
            minutes=BLOCK_DURATION_MINUTES
        )
    )

    existing_block = (
        db.query(BlockedIP)
        .filter(
            BlockedIP.ip == ip,
            BlockedIP.is_active.is_(True),
        )
        .first()
    )

    if existing_block is not None:

        existing_until = existing_block.blocked_until

        if existing_until.tzinfo is None:

            existing_until = existing_until.replace(
                tzinfo=timezone.utc
            )

        if existing_until > now:

            existing_block.reason = reason
            existing_block.prediction = prediction
            existing_block.confidence = confidence
            existing_block.blocked_until = blocked_until
            existing_block.is_active = True

            db.add(existing_block)
            db.commit()
            db.refresh(existing_block)

            block = existing_block

        else:

            existing_block.is_active = False
            db.add(existing_block)

            block = BlockedIP(
                ip=ip,
                reason=reason,
                prediction=prediction,
                confidence=confidence,
                blocked_at=now,
                blocked_until=blocked_until,
                is_active=True,
            )

            db.add(block)
            db.commit()
            db.refresh(block)

    else:

        block = BlockedIP(
            ip=ip,
            reason=reason,
            prediction=prediction,
            confidence=confidence,
            blocked_at=now,
            blocked_until=blocked_until,
            is_active=True,
        )

        db.add(block)
        db.commit()
        db.refresh(block)

    # ---------------------------------------------------------
    # Dashboard alert
    # ---------------------------------------------------------

    create_alert(
        db,
        session_id=session_id,
        ip=ip,
        prediction=prediction,
        confidence=confidence,
        action="BLOCK",
        reason=reason,
        url_score=url_score,
        behavior_score=behavior_score,
        risk_score=risk_score,
        severity=severity,
    )

    return block