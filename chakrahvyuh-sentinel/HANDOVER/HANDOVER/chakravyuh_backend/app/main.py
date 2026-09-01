from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Existing URL-risk pipeline
from app.feature_extractor import extract_features
from app.agent import decide
from app.model_loader import lr_model, rf_model, xgb_model
from app.utils import track_ip

# Security / behavior pipeline
from app.database import init_db
from app.security_middleware import IPBlockMiddleware
from app.request_logging_middleware import RequestLoggingMiddleware
from app.dashboard_routes import router as dashboard_router

app = FastAPI(title="Chakravyuh Sentinel API")

# Middleware: innermost first, CORS outermost (handles OPTIONS preflight)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(IPBlockMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
