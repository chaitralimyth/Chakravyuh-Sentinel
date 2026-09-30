"""
Chakravyuh Sentinel Unified Security Evaluation Pipeline

Connects:
Traffic/Session -> Behavior ML + URL ML -> Dynamic Risk Engine -> Adaptive Security Agent -> Alerts/Incidents/Blocking
"""

from typing import Any, Optional
from sqlalchemy.orm import Session

from app.db_models import RequestLog, SessionRecord
from app.behavior_feature_extractor import build_feature_vector, build_feature_dict
from app.behavior_agent import run_behavior_prediction
from app.feature_extractor import extract_features
from app.model_loader import predict_url
from app.risk_engine import (
    calculate_risk,
    calculate_request_rate_score,
    calculate_auth_failure_score,
    calculate_endpoint_risk,
)
from app.adaptive_agent import decide_adaptive_security
from app.blocking_service import block_ip
from app.alert_service import create_alert


def evaluate_session_security(
    db: Session,
    session: SessionRecord,
    client_ip: str,
    current_url: str = "",
) -> dict[str, Any]:
    """
    Evaluates session traffic against the unified Chakravyuh Sentinel security pipeline:
    1. Collects session request logs
    2. Runs Behavior ML prediction & URL ML prediction
    3. Computes normalized composite risk score (0-100) via Dynamic Risk Engine
    4. Applies Adaptive Security Agent decision logic (ALLOW, MONITOR, RATE_LIMIT, BLOCK)
    5. Enforces decisions with zero duplication (BLOCK -> block_ip once; MONITOR/RATE_LIMIT -> create_alert; ALLOW -> no alert)
    """
    rows = (
        db.query(RequestLog)
        .filter(RequestLog.session_id == session.session_id)
        .order_by(RequestLog.timestamp.asc())
        .all()
    )

    if not rows:
        return {
            "evaluated": False,
            "action": "ALLOW",
            "risk_score": 0.0,
            "severity": "LOW",
        }

    # 1. Behavior ML detection
    feature_vector = build_feature_vector(rows)
    behavior_result = run_behavior_prediction(feature_vector)
    behavior_attack_prob = float(behavior_result.get("attack_probability", 0.0) or 0.0)
    behavior_pred = behavior_result.get("prediction", "normal")
    behavior_conf = behavior_result.get("confidence")

    # 2. URL ML detection
    url_to_eval = current_url or (rows[-1].endpoint if rows else "/")
    url_attack_prob = 0.0
    url_conf = None
    url_pred = "normal"
    try:
        url_features = extract_features(url_to_eval)
        url_result = predict_url(url_features)
        url_attack_prob = float(url_result.get("attack_probability", 0.0) or 0.0)
        url_conf = url_result.get("confidence")
        url_pred = url_result.get("prediction", "normal")
    except Exception as e:
        print("[SENTINEL URL ML EVAL ERROR]", repr(e))

    # 3. Contextual feature extraction
    features_dict = build_feature_dict(rows)
    request_rate_score = calculate_request_rate_score(features_dict.get("max_requests_per_second", 0))
    auth_failure_score = calculate_auth_failure_score(features_dict.get("auth_failure_ratio", 0.0))
    endpoint_risk_score = calculate_endpoint_risk(url_to_eval)

    # 4. Harshad Dynamic Risk Engine (composite 0-100 scoring)
    risk_dict = calculate_risk(
        url_attack_probability=url_attack_prob,
        behavior_attack_probability=behavior_attack_prob,
        request_rate_score=request_rate_score,
        auth_failure_score=auth_failure_score,
        endpoint_risk_score=endpoint_risk_score,
    )
    risk_score = float(risk_dict["risk_score"])
    severity = str(risk_dict["severity"])

    # 5. Adaptive Security Agent (sole policy decision authority)
    context = {
        "behavior_prediction": behavior_pred,
        "behavior_score": behavior_attack_prob,
        "url_score": url_attack_prob,
        "url_risk": url_pred,
        "request_rate_score": request_rate_score,
        "auth_failure_ratio": features_dict.get("auth_failure_ratio", 0.0),
        "admin_endpoint_access": features_dict.get("admin_endpoint_access", 0),
        "request_count": session.request_count,
    }

    decision = decide_adaptive_security(
        risk_score=risk_score,
        confidence=behavior_conf if behavior_conf is not None else url_conf,
        severity=severity,
        context=context,
        session_id=session.session_id,
        source_ip=client_ip,
        db=db,
        enforce_block=False,  # Enforce explicitly below to guarantee single operation
    )

    action = decision["action"]
    reasons = decision.get("reasons", [])
    primary_reason = reasons[0] if reasons else f"Adaptive security policy: {action}"

    # 6. Deterministic action enforcement & correlation
    if action == "BLOCK":
        session.status = "blocked"
        db.add(session)
        db.commit()

        # block_ip creates BlockedIP and calls create_alert, which updates incident correlation
        block_ip(
            db=db,
            ip=client_ip,
            reason=primary_reason[:255],
            prediction=behavior_pred,
            confidence=decision.get("confidence"),
            session_id=session.session_id,
            url_score=url_attack_prob,
            behavior_score=behavior_attack_prob,
            risk_score=risk_score,
            severity=severity,
        )

    elif action in ("MONITOR", "RATE_LIMIT"):
        # create_alert records the alert and correlates with SecurityIncident
        create_alert(
            db=db,
            ip=client_ip,
            action=action,
            reason=primary_reason[:255],
            session_id=session.session_id,
            prediction=behavior_pred,
            confidence=decision.get("confidence"),
            url_score=url_attack_prob,
            behavior_score=behavior_attack_prob,
            risk_score=risk_score,
            severity=severity,
        )

    # For ALLOW: no alert or block is created.

    return {
        "evaluated": True,
        "action": action,
        "risk_score": risk_score,
        "severity": severity,
        "components": risk_dict.get("components", {}),
        "decision": decision,
    }
