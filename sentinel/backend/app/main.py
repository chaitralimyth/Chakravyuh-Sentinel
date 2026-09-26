from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Existing URL-risk pipeline
from app.feature_extractor import extract_features
from app.agent import decide
from app.model_loader import lr_model, rf_model, xgb_model
from app.utils import track_ip

# Security / behavior pipeline
from app.database import init_db, get_db
from app.security_middleware import IPBlockMiddleware
from app.request_logging_middleware import RequestLoggingMiddleware
from app.db_models import SecurityAlert


app = FastAPI()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

@app.on_event("startup")
def _init_security_db():
    init_db()


# ============================================================
# MIDDLEWARE
# ============================================================
#
# Order matters.
#
# CORS
#   ↓
# IPBlockMiddleware
#   ↓
# RequestLoggingMiddleware
#   ↓
# Routes
#
# The last middleware added runs first / is outermost.
# ============================================================

app.add_middleware(
    RequestLoggingMiddleware
)

app.add_middleware(
    IPBlockMiddleware
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# SECURITY ALERTS
# ============================================================

@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    """
    Admin dashboard endpoint:
    Fetch the latest recorded security alerts.
    """

    alerts = (
        db.query(SecurityAlert)
        .order_by(SecurityAlert.created_at.desc())
        .limit(100)
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
            "created_at": (
                a.created_at.isoformat()
                if a.created_at
                else None
            ),
            "is_read": a.is_read,
        }
        for a in alerts
    ]


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "message": "Chakravyuh API running 🚀"
    }


# ============================================================
# URL RISK HELPERS
# ============================================================

def confidence_label(score: float):
    if score > 0.8:
        return "HIGH RISK"
    elif score > 0.4:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


# ============================================================
# URL PREDICTION
# ============================================================

@app.post("/predict")
def predict(url: str, request: Request):

    try:

        # ----------------------------------------------------
        # Step 1: Extract URL features
        # ----------------------------------------------------

        features = extract_features(url)


        # ----------------------------------------------------
        # Step 2: Get model confidences
        # ----------------------------------------------------

        lr_score = lr_model.predict_proba([features])[0][1]
        rf_score = rf_model.predict_proba([features])[0][1]
        xgb_score = xgb_model.predict_proba([features])[0][1]


        # ----------------------------------------------------
        # Step 3: Combine model scores
        # ----------------------------------------------------

        final_score = (
            lr_score +
            rf_score +
            xgb_score
        ) / 3


        # ----------------------------------------------------
        # Step 4: Agent decision
        # ----------------------------------------------------

        action, reasons = decide(
            final_score,
            url
        )


        # ----------------------------------------------------
        # Step 5: Align risk level with action
        # ----------------------------------------------------

        if action == "BLOCK":
            risk = "HIGH RISK"

        elif action == "ALERT":
            risk = "MEDIUM RISK"

        else:
            risk = confidence_label(final_score)


        # ----------------------------------------------------
        # Step 6: Track IP
        # ----------------------------------------------------

        client_ip = request.client.host
        request_count = track_ip(client_ip)


        # ----------------------------------------------------
        # Step 7: Request-rate rule
        # ----------------------------------------------------

        if request_count > 10:

            reasons.append(
                "Too many requests from same user"
            )

            action = "ALERT"
            risk = "MEDIUM RISK"


        # ----------------------------------------------------
        # Step 8: Return response
        # ----------------------------------------------------

        return {
            "url": url,

            "model_confidence": {
                "logistic_regression": float(lr_score),
                "random_forest": float(rf_score),
                "xgboost": float(xgb_score)
            },

            "final_score": float(final_score),

            "risk_level": risk,

            "action": action,

            "reasons": reasons,

            "request_count": request_count
        }


    except Exception as e:

        return {
            "error": str(e)
        }