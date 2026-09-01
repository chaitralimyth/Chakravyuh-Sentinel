"""
Read-only API endpoints for the admin dashboard.

These routes only query PostgreSQL — they do not run ML, blocking, or alerts.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.db_models import BlockedIP, RequestLog, SecurityAlert, SessionRecord

router = APIRouter(tags=["dashboard"])


def _iso(dt) -> Optional[str]:
    return dt.isoformat() if dt else None


@router.get("/alerts")
def list_alerts(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    unread_only: bool = False,
):
    """Fetch security alerts for the dashboard."""
    query = db.query(SecurityAlert)
    if unread_only:
        query = query.filter(SecurityAlert.is_read.is_(False))

    alerts = (
        query.order_by(SecurityAlert.created_at.desc())
        .limit(limit)
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
            "created_at": _iso(a.created_at),
            "is_read": a.is_read,
        }
        for a in alerts
    ]


@router.get("/blocked-ips")
def list_blocked_ips(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    active_only: bool = True,
):
    """Fetch blocked IP records."""
    query = db.query(BlockedIP)
    if active_only:
        query = query.filter(BlockedIP.is_active.is_(True))

    blocks = (
        query.order_by(BlockedIP.blocked_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": b.id,
            "ip": b.ip,
            "reason": b.reason,
            "prediction": b.prediction,
            "confidence": b.confidence,
            "blocked_at": _iso(b.blocked_at),
            "blocked_until": _iso(b.blocked_until),
            "is_active": b.is_active,
        }
        for b in blocks
    ]


@router.get("/requests")
def list_requests(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ip: Optional[str] = None,
):
    """Fetch request log entries."""
    query = db.query(RequestLog)
    if ip:
        query = query.filter(RequestLog.ip == ip)

    logs = (
        query.order_by(RequestLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        {
            "id": r.id,
            "timestamp": _iso(r.timestamp),
            "ip": r.ip,
            "method": r.method,
            "endpoint": r.endpoint,
            "status_code": r.status_code,
            "request_size": r.request_size,
            "response_size": r.response_size,
            "response_time_ms": r.response_time_ms,
            "query_length": r.query_length,
            "session_id": r.session_id,
        }
        for r in logs
    ]


@router.get("/sessions")
def list_sessions(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    status: Optional[str] = None,
):
    """Fetch session records."""
    query = db.query(SessionRecord)
    if status:
        query = query.filter(SessionRecord.status == status)

    sessions = (
        query.order_by(SessionRecord.last_activity.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "session_id": s.session_id,
            "ip": s.ip,
            "started_at": _iso(s.started_at),
            "last_activity": _iso(s.last_activity),
            "duration_seconds": s.duration_seconds,
            "status": s.status,
            "request_count": s.request_count,
        }
        for s in sessions
    ]


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Dashboard header KPIs."""
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)

    try:
        total_requests = db.query(RequestLog).count()
        active_sessions = (
            db.query(SessionRecord)
            .filter(SessionRecord.status == "active")
            .count()
        )
        total_alerts = db.query(SecurityAlert).count()
        unread_alerts = (
            db.query(SecurityAlert)
            .filter(SecurityAlert.is_read.is_(False))
            .count()
        )
        active_blocked_ips = (
            db.query(BlockedIP)
            .filter(BlockedIP.is_active.is_(True))
            .count()
        )
        requests_24h = (
            db.query(RequestLog)
            .filter(RequestLog.timestamp >= since_24h)
            .count()
        )
    except Exception:
        total_requests = 0
        active_sessions = 0
        total_alerts = 0
        unread_alerts = 0
        active_blocked_ips = 0
        requests_24h = 0

    return {
        "status": "running",
        "total_requests": total_requests,
        "active_sessions": active_sessions,
        "total_alerts": total_alerts,
        "unread_alerts": unread_alerts,
        "active_blocked_ips": active_blocked_ips,
        "requests_24h": requests_24h,
    }


@router.get("/statistics")
def get_statistics(db: Session = Depends(get_db)):
    """Extended analytics for dashboard charts."""
    now = datetime.now(timezone.utc)
    since_7d = now - timedelta(days=7)

    # Agent decision distribution from alerts
    alert_rows = db.query(
        SecurityAlert.prediction,
        func.count(SecurityAlert.id),
    ).group_by(SecurityAlert.prediction).all()

    decision_counts = {"attacker": 0, "normal": 0, "other": 0}
    for prediction, count in alert_rows:
        key = (prediction or "other").lower()
        if key in decision_counts:
            decision_counts[key] = count
        else:
            decision_counts["other"] += count

    total_decisions = sum(decision_counts.values()) or 1

    # HTTP status code distribution (last 7 days)
    status_rows = (
        db.query(RequestLog.status_code, func.count(RequestLog.id))
        .filter(RequestLog.timestamp >= since_7d)
        .group_by(RequestLog.status_code)
        .all()
    )
    status_distribution = {str(code): count for code, count in status_rows}

    # Daily request counts (last 7 days)
    daily_rows = (
        db.query(
            func.date(RequestLog.timestamp).label("day"),
            func.count(RequestLog.id),
        )
        .filter(RequestLog.timestamp >= since_7d)
        .group_by(func.date(RequestLog.timestamp))
        .order_by(func.date(RequestLog.timestamp))
        .all()
    )
    requests_by_day = [
        {"date": str(day), "count": count}
        for day, count in daily_rows
    ]

    # Daily blocked IP counts (last 7 days)
    blocked_rows = (
        db.query(
            func.date(BlockedIP.blocked_at).label("day"),
            func.count(BlockedIP.id),
        )
        .filter(BlockedIP.blocked_at >= since_7d)
        .group_by(func.date(BlockedIP.blocked_at))
        .order_by(func.date(BlockedIP.blocked_at))
        .all()
    )
    blocked_by_day = [
        {"date": str(day), "count": count}
        for day, count in blocked_rows
    ]

    # Top IPs by request count
    top_ip_rows = (
        db.query(RequestLog.ip, func.count(RequestLog.id).label("cnt"))
        .filter(RequestLog.timestamp >= since_7d)
        .group_by(RequestLog.ip)
        .order_by(func.count(RequestLog.id).desc())
        .limit(10)
        .all()
    )
    top_ips = [{"ip": ip, "request_count": cnt} for ip, cnt in top_ip_rows]

    return {
        "decision_distribution": {
            "attacker": decision_counts["attacker"],
            "normal": decision_counts["normal"],
            "other": decision_counts["other"],
            "attacker_pct": round(decision_counts["attacker"] / total_decisions * 100, 1),
            "normal_pct": round(decision_counts["normal"] / total_decisions * 100, 1),
            "total": total_decisions,
        },
        "status_distribution": status_distribution,
        "requests_by_day": requests_by_day,
        "blocked_by_day": blocked_by_day,
        "top_ips": top_ips,
    }
