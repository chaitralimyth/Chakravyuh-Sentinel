"""
Manages the blocked_ips table: checking active blocks, expiring old ones,
and creating new blocks when the behavior agent returns BLOCK.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session as DBSession

from app.db_models import BlockedIP
from app.config import BLOCK_DURATION_MINUTES
from app.alert_service import create_alert


def is_ip_blocked(db: DBSession, ip: str) -> bool:
    now = datetime.now(timezone.utc)

    active_blocks = (
        db.query(BlockedIP)
        .filter(BlockedIP.ip == ip, BlockedIP.is_active.is_(True))
        .all()
    )

    still_blocked = False
    for block in active_blocks:
        blocked_until = block.blocked_until
        if blocked_until.tzinfo is None:
            blocked_until = blocked_until.replace(tzinfo=timezone.utc)

        if blocked_until <= now:
            # expire it
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
) -> BlockedIP:
    now = datetime.now(timezone.utc)
    blocked_until = now + timedelta(minutes=BLOCK_DURATION_MINUTES)

    existing_block = (
        db.query(BlockedIP)
        .filter(BlockedIP.ip == ip, BlockedIP.is_active.is_(True))
        .first()
    )

    is_expired = False
    if existing_block is not None:
        existing_blocked_until = existing_block.blocked_until
        if existing_blocked_until.tzinfo is None:
            existing_blocked_until = existing_blocked_until.replace(tzinfo=timezone.utc)
        is_expired = existing_blocked_until <= now

    if existing_block is not None and not is_expired:
        # Active, non-expired block already exists for this IP — extend/update
        # it instead of creating a second active row, so exactly one active
        # block per IP is guaranteed.
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
        if existing_block is not None and is_expired:
            # Stale expired row — deactivate it before creating the new one.
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

    create_alert(
        db,
        session_id=session_id,
        ip=ip,
        prediction=prediction,
        confidence=confidence,
        action="BLOCK",
        reason=reason,
    )

    return block