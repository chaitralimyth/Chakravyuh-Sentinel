"""
Read-only API endpoints for the admin dashboard.

These routes only query PostgreSQL — they do not run ML, blocking, or alerts.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.db_models import BlockedIP, RequestLog, SecurityAlert, SessionRecord
from app.sqli_detector import detect_sqli

router = APIRouter(tags=["dashboard"])


def _iso(dt) -> Optional[str]:
    """Serialize datetime to standard UTC ISO-8601 string with Z suffix."""
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _alerts_for_source(db: Session, source_site: str):
    query = db.query(SecurityAlert)
    if source_site.strip().lower() != "all":
        query = query.join(
            SessionRecord,
            SecurityAlert.session_id == SessionRecord.session_id,
        ).filter(SessionRecord.source_site == source_site.strip().lower())
    return query


@router.get("/alerts")
def list_alerts(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    unread_only: bool = False,
    source_site: str = "x-beauty",
):
    """Fetch security alerts for the dashboard."""
    query = _alerts_for_source(db, source_site)
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
            "url_score": a.url_score,
            "behavior_score": a.behavior_score,
            "risk_score": a.risk_score,
            "severity": a.severity,
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
    source_site: str = "x-beauty",
    endpoint: Optional[str] = None,
    session_id: Optional[str] = None,
):
    """Fetch request log entries with optional filters."""
    for param_name, param_val in [("ip", ip), ("endpoint", endpoint), ("session_id", session_id)]:
        if param_val and detect_sqli(param_val)["is_sqli"]:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid {param_name} parameter: SQL injection pattern detected",
            )

    query = db.query(RequestLog)
    if ip:
        query = query.filter(RequestLog.ip == ip)
    source_site = (source_site or "").strip().lower()
    if source_site and source_site != "all":
        query = query.filter(RequestLog.source_site == source_site)
    if endpoint:
        query = query.filter(RequestLog.endpoint.contains(endpoint))
    if session_id:
        query = query.filter(RequestLog.session_id == session_id)

    logs = (
        query.order_by(RequestLog.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        {
            "id": r.id,
            "timestamp": _iso(r.timestamp),
            "ip": r.ip,
            "source_site": r.source_site,
            "method": r.method,
            "endpoint": r.endpoint,
            "status_code": r.status_code,
            "request_size": r.request_size,
            "response_size": r.response_size,
            "response_time_ms": r.response_time_ms,
            "query_length": r.query_length,
            "query_data": r.query_data,
            "session_id": r.session_id,
        }
        for r in logs
    ]


@router.get("/sessions")
def list_sessions(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    status: Optional[str] = None,
    source_site: str = "x-beauty",
):
    """Fetch session records."""
    query = db.query(SessionRecord)
    if status:
        query = query.filter(SessionRecord.status == status)
    source_site = source_site.strip().lower()
    if source_site != "all":
        query = query.filter(SessionRecord.source_site == source_site)

    sessions = (
        query.order_by(SessionRecord.last_activity.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "session_id": s.session_id,
            "ip": s.ip,
            "source_site": s.source_site,
            "started_at": _iso(s.started_at),
            "last_activity": _iso(s.last_activity),
            "duration_seconds": s.duration_seconds,
            "status": s.status,
            "request_count": s.request_count,
        }
        for s in sessions
    ]


@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    source_site: str = "x-beauty",
):
    """Dashboard header KPIs."""
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    source_site = source_site.strip().lower()

    request_query = db.query(RequestLog)
    session_query = db.query(SessionRecord).filter(SessionRecord.status == "active")
    if source_site != "all":
        request_query = request_query.filter(RequestLog.source_site == source_site)
        session_query = session_query.filter(SessionRecord.source_site == source_site)
    total_requests = request_query.count()
    active_sessions = session_query.count()
    alert_query = _alerts_for_source(db, source_site)
    total_alerts = alert_query.count()
    unread_alerts = alert_query.filter(SecurityAlert.is_read.is_(False)).count()
    active_blocked_ips = (
        db.query(BlockedIP)
        .filter(BlockedIP.is_active.is_(True))
        .count()
    )
    requests_24h_query = request_query.filter(RequestLog.timestamp >= since_24h)
    requests_24h = requests_24h_query.count()

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
def get_statistics(
    db: Session = Depends(get_db),
    source_site: str = "x-beauty",
):
    """Extended analytics for dashboard charts."""
    now = datetime.now(timezone.utc)
    since_7d = now - timedelta(days=7)
    source_site = source_site.strip().lower()

    # Agent decision distribution from alerts
    alert_rows = _alerts_for_source(db, source_site).with_entities(
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
    request_query = db.query(RequestLog)
    if source_site != "all":
        request_query = request_query.filter(RequestLog.source_site == source_site)

    status_rows = (
        request_query.with_entities(RequestLog.status_code, func.count(RequestLog.id))
        .filter(RequestLog.timestamp >= since_7d)
        .group_by(RequestLog.status_code)
        .all()
    )
    status_distribution = {str(code): count for code, count in status_rows}

    # Daily request counts (last 7 days)
    daily_rows = (
        request_query.with_entities(
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
        request_query.with_entities(RequestLog.ip, func.count(RequestLog.id).label("cnt"))
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
