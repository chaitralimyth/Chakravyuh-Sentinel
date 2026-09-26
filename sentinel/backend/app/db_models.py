"""
SQLAlchemy ORM models for the security system.

Four tables, matching the schema requested:
    - request_logs
    - sessions
    - blocked_ips
    - security_alerts
"""

import uuid

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
)
from sqlalchemy.sql import func

from app.database import Base


def new_session_id() -> str:
    return uuid.uuid4().hex


class SessionRecord(Base):
    """A behavioral session: same IP, grouped by <=30 min inactivity gaps."""

    __tablename__ = "sessions"

    session_id = Column(String(32), primary_key=True, default=new_session_id)
    ip = Column(String(64), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_activity = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    duration_seconds = Column(Float, default=0.0, nullable=False)
    status = Column(String(16), default="active", nullable=False)  # active | closed | blocked
    request_count = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("ix_sessions_ip_status", "ip", "status"),
    )


class RequestLog(Base):
    """One row per raw incoming request, used to derive the 28 behavior features."""

    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(32), ForeignKey("sessions.session_id"), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ip = Column(String(64), nullable=False, index=True)
    method = Column(String(10), nullable=False)
    endpoint = Column(String(512), nullable=False)
    status_code = Column(Integer, nullable=False)
    request_size = Column(Integer, default=0, nullable=False)
    response_size = Column(Integer, default=0, nullable=False)
    response_time_ms = Column(Float, default=0.0, nullable=False)
    query_length = Column(Integer, default=0, nullable=False)
    query_data = Column(Text, nullable=True)  # raw query string, safely truncated if huge


class BlockedIP(Base):
    """Active/expired IP blocks issued by the behavior agent."""

    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), nullable=False, index=True)
    reason = Column(String(255), nullable=False)
    prediction = Column(String(32), nullable=True)   # 'attacker' / 'normal'
    confidence = Column(Float, nullable=True)         # threat score, if model exposes it
    blocked_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    blocked_until = Column(DateTime(timezone=True), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_blocked_ips_ip_active", "ip", "is_active"),
    )


class SecurityAlert(Base):
    """Dashboard-facing record of a BLOCK (or other agent) decision."""

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(32), ForeignKey("sessions.session_id"), nullable=True, index=True)
    ip = Column(String(64), nullable=False, index=True)
    prediction = Column(String(32), nullable=True)
    confidence = Column(Float, nullable=True)
    action = Column(String(16), nullable=False)  # BLOCK / ALLOW (only BLOCK is written today)
    reason = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
