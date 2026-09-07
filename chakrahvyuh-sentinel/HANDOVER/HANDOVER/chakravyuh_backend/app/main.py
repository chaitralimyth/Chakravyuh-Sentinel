from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import Optional

# Existing URL-risk pipeline
from app.feature_extractor import extract_features
from app.agent import decide
from app.model_loader import lr_model, rf_model, xgb_model
from app.utils import track_ip

# Security / behavior pipeline
from app.database import init_db, SessionLocal
from app.security_middleware import IPBlockMiddleware
from app.request_logging_middleware import RequestLoggingMiddleware
from app.dashboard_routes import router as dashboard_router
from app.config import ALLOWED_ORIGINS, SESSION_EVAL_THRESHOLD
from app.db_models import RequestLog
from app.session_builder import get_or_create_session, touch_session
from app.behavior_feature_extractor import build_feature_vector
from app.behavior_agent import run_behavior_prediction
from app.blocking_service import block_ip

app = FastAPI(title="Chakravyuh Sentinel API")

# Middleware: innermost first, CORS outermost (handles OPTIONS preflight)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(IPBlockMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dashboard read-only routes
app.include_router(dashboard_router)


@app.on_event("startup")
def _init_security_db():
    init_db()


class URLPayload(BaseModel):
    url: str


class TrafficIngestRequest(BaseModel):
    """Request schema for external traffic ingestion from singhaman.me"""
    ip: str = Field(..., description="Client IP address")
    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    endpoint: str = Field(..., description="URL path")
    status_code: int = Field(..., description="HTTP response status code")
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    request_size: int = Field(default=0, description="Request size in bytes")
    response_size: int = Field(default=0, description="Response size in bytes")
    response_time_ms: float = Field(default=0.0, description="Response time in milliseconds")
    query_length: int = Field(default=0, description="Query string length")
    query_data: str = Field(default="", description="Query string data")


@app.get("/")
def home():
    return {"message": "Chakravyuh API running 🚀"}


def confidence_label(score: float):
    if score > 0.8:
        return "HIGH RISK"
    elif score > 0.4:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


@app.post("/analyze")
@app.post("/predict")
def analyze_url(payload: URLPayload, request: Request):
    """Processes URL risk evaluation for both frontend /analyze and /predict."""
    url = payload.url

    try:
        features = extract_features(url)

        lr_score = lr_model.predict_proba([features])[0][1]
        rf_score = rf_model.predict_proba([features])[0][1]
        xgb_score = xgb_model.predict_proba([features])[0][1]

        final_score = (lr_score + rf_score + xgb_score) / 3

        action, reasons = decide(final_score, url)

        if action == "BLOCK":
            risk = "HIGH RISK"
        elif action == "ALERT":
            risk = "MEDIUM RISK"
        else:
            risk = confidence_label(final_score)

        client_ip = request.client.host
        request_count = track_ip(client_ip)

        if request_count > 10:
            reasons.append("Too many requests from same user")
            action = "ALERT"
            risk = "MEDIUM RISK"

        return {
            "url": url,
            "score": float(final_score),
            "final_score": float(final_score),
            "risk_level": risk,
            "action": action,
            "reasons": reasons,
            "request_count": request_count,
            "model_confidence": {
                "logistic_regression": float(lr_score),
                "random_forest": float(rf_score),
                "xgboost": float(xgb_score),
            },
        }

    except Exception as e:
        return {"error": str(e), "score": 0.5}


@app.post("/api/ingest-traffic")
def ingest_traffic(payload: TrafficIngestRequest):
    """
    Ingest external traffic data from singhaman.me into the Sentinel pipeline.
    
    This endpoint receives traffic information and processes it through the existing
    security pipeline: RequestLog → Session Builder → Behavior Feature Extraction → 
    Behavior Model → Behavior Agent → Alert/Blocking
    """
    db = SessionLocal()
    try:
        # Parse timestamp
        try:
            request_timestamp = datetime.fromisoformat(payload.timestamp.replace('Z', '+00:00'))
            if request_timestamp.tzinfo is None:
                request_timestamp = request_timestamp.replace(tzinfo=timezone.utc)
        except ValueError:
            # Fallback to current time if timestamp parsing fails
            request_timestamp = datetime.now(timezone.utc)
        
        # Get or create session for this IP
        session = get_or_create_session(db, payload.ip)
        
        # Create request log entry
        log = RequestLog(
            session_id=session.session_id,
            timestamp=request_timestamp,
            ip=payload.ip,
            method=payload.method,
            endpoint=payload.endpoint,
            status_code=payload.status_code,
            request_size=payload.request_size,
            response_size=payload.response_size,
            response_time_ms=payload.response_time_ms,
            query_length=payload.query_length,
            query_data=payload.query_data[:2000],  # truncate to avoid unbounded storage
        )
        db.add(log)
        db.commit()
        
        # Update session
        session = touch_session(db, session)
        
        # Run behavior evaluation if threshold reached
        if session.request_count > 0 and session.request_count % SESSION_EVAL_THRESHOLD == 0:
            rows = (
                db.query(RequestLog)
                .filter(RequestLog.session_id == session.session_id)
                .order_by(RequestLog.timestamp.asc())
                .all()
            )
            feature_vector = build_feature_vector(rows)
            decision = run_behavior_prediction(feature_vector)
            
            if decision["action"] == "BLOCK":
                session.status = "blocked"
                db.add(session)
                db.commit()
                
                block_ip(
                    db,
                    ip=payload.ip,
                    reason=decision["reason"],
                    prediction=decision["prediction"],
                    confidence=decision["confidence"],
                    session_id=session.session_id,
                )
        
        return {
            "success": True,
            "message": "Traffic ingested successfully",
            "session_id": session.session_id,
            "request_count": session.request_count
        }
        
    except Exception as e:
        db.rollback()
        return {
            "success": False,
            "message": f"Failed to ingest traffic: {str(e)}"
        }
    finally:
        db.close()
