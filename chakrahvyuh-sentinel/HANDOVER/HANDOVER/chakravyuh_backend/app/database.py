"""
SQLAlchemy engine/session setup for the security system's PostgreSQL layer.

This is intentionally separate from the ML pipelines — nothing here imports
or touches model_loader.py, feature_extractor.py, or agent.py (URL pipeline).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import DATABASE_URL

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency-style generator for a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all security-system tables if they don't already exist.

    Safe to call on every app startup — create_all() is a no-op for
    tables that already exist. Does NOT touch any pre-existing tables
    outside this module's models (there are none in this project yet).
    """
    from app import db_models  # noqa: F401  (registers models on Base)

    Base.metadata.create_all(bind=engine)
