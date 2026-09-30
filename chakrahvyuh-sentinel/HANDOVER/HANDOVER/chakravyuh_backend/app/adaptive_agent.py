"""
Deterministic Adaptive Security Agent for Chakravyuh Sentinel.

This module acts as the security decision layer downstream of the
Dynamic Risk Scoring Engine. It evaluates normalized risk scores (0-100),
certainty metrics, and optional contextual signals to output a deterministic,
structured, and explainable security action:

    0 - 29   -> ALLOW
    30 - 59  -> MONITOR
    60 - 79  -> RATE_LIMIT
    80 - 100 -> BLOCK

Key Properties:
- Deterministic: Identical inputs always produce identical decisions.
- Explainable: Structured, human-readable reasons for every action.
- Honest Enforcement: Explicitly indicates that RATE_LIMIT is a decision
  without fake throttling enforcement.
- Side-Effect Free by Default: enforce_block=False by default to protect
  the live pipeline until explicitly enabled.
- Resilient: Missing optional context degrades gracefully without crashing.
- No LLMs, reinforcement learning, or heuristic drift.
"""

from datetime import datetime, timezone
import math
from typing import Any, Optional, Union

from app.config import (
    RISK_ALLOW_MAX,
    RISK_MONITOR_MIN,
    RISK_MONITOR_MAX,
    RISK_RATE_LIMIT_MIN,
    RISK_RATE_LIMIT_MAX,
    RISK_BLOCK_MIN,
)

ACTION_ALLOW = "ALLOW"
ACTION_MONITOR = "MONITOR"
ACTION_RATE_LIMIT = "RATE_LIMIT"
ACTION_BLOCK = "BLOCK"

VALID_ACTIONS = {ACTION_ALLOW, ACTION_MONITOR, ACTION_RATE_LIMIT, ACTION_BLOCK}

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

VALID_SEVERITIES = {SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL}


def _derive_severity(risk_score: float, allow_max: int, monitor_max: int, rate_limit_max: int) -> str:
    """Deterministically map a normalized risk score (0-100) to a severity label."""
    if risk_score <= allow_max:
        return SEVERITY_LOW
    if risk_score <= monitor_max:
        return SEVERITY_MEDIUM
    if risk_score <= rate_limit_max:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL


class AdaptiveSecurityAgent:
    """
    Deterministic Adaptive Security Decision Engine.

    Consumes normalized output from the Dynamic Risk Scoring Engine
    and determines the appropriate security action along with structured
    explanations and contextual contributing factors.
    """

    def __init__(
        self,
        allow_max: int = RISK_ALLOW_MAX,
        monitor_min: int = RISK_MONITOR_MIN,
        monitor_max: int = RISK_MONITOR_MAX,
        rate_limit_min: int = RISK_RATE_LIMIT_MIN,
        rate_limit_max: int = RISK_RATE_LIMIT_MAX,
        block_min: int = RISK_BLOCK_MIN,
    ):
        self.allow_max = allow_max
        self.monitor_min = monitor_min
        self.monitor_max = monitor_max
        self.rate_limit_min = rate_limit_min
        self.rate_limit_max = rate_limit_max
        self.block_min = block_min

        # Validate threshold coherence
        if not (0 <= self.allow_max < self.monitor_min <= self.monitor_max < self.rate_limit_min <= self.rate_limit_max < self.block_min <= 100):
            raise ValueError("Invalid threshold configuration: thresholds must be strictly ascending within [0, 100].")

    def get_policy_summary(self) -> dict[str, Any]:
        """Return the active threshold configuration for policy introspection."""
        return {
            "ALLOW": {"min": 0, "max": self.allow_max, "severity": SEVERITY_LOW},
            "MONITOR": {"min": self.monitor_min, "max": self.monitor_max, "severity": SEVERITY_MEDIUM},
            "RATE_LIMIT": {"min": self.rate_limit_min, "max": self.rate_limit_max, "severity": SEVERITY_HIGH},
            "BLOCK": {"min": self.block_min, "max": 100, "severity": SEVERITY_CRITICAL},
        }

    def _validate_inputs(
        self,
        risk_score: Any,
        confidence: Optional[float],
        severity: Optional[str],
    ) -> tuple[float, Optional[float], str]:
        """Validate risk_score, confidence, and severity strictly."""
        if risk_score is None:
            raise ValueError("risk_score is required and cannot be None.")

        if not isinstance(risk_score, (int, float)) or isinstance(risk_score, bool):
            raise TypeError(f"risk_score must be a numeric value (int or float), got {type(risk_score).__name__}.")

        if math.isnan(risk_score) or math.isinf(risk_score):
            raise ValueError("risk_score must be a finite real number.")

        float_score = float(risk_score)
        if float_score < 0.0 or float_score > 100.0:
            raise ValueError(f"risk_score must be between 0 and 100, got {float_score}.")

        validated_confidence: Optional[float] = None
        if confidence is not None:
            if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
                raise TypeError(f"confidence must be a float between 0.0 and 1.0, got {type(confidence).__name__}.")
            if math.isnan(confidence) or math.isinf(confidence):
                raise ValueError("confidence must be a finite real number.")
            conf_val = float(confidence)
            if conf_val < 0.0 or conf_val > 1.0:
                raise ValueError(f"confidence must be between 0.0 and 1.0, got {conf_val}.")
            validated_confidence = conf_val

        validated_severity: str
        if severity is not None:
            sev_upper = str(severity).strip().upper()
            if sev_upper in VALID_SEVERITIES:
                validated_severity = sev_upper
            else:
                validated_severity = _derive_severity(float_score, self.allow_max, self.monitor_max, self.rate_limit_max)
        else:
            validated_severity = _derive_severity(float_score, self.allow_max, self.monitor_max, self.rate_limit_max)

        return float_score, validated_confidence, validated_severity

    def _build_reasons_and_factors(
        self,
        action: str,
        risk_score: float,
        confidence: Optional[float],
        context: dict[str, Any],
    ) -> tuple[list[str], dict[str, Any]]:
        """
        Build concrete explainability reasons and extract normalized contributing factors.
        Uses real signals only and avoids unsupported claims (e.g. does not claim
        'confirmed attack' solely because the score crossed the BLOCK threshold).
        """
        reasons: list[str] = []
        contributing_factors: dict[str, Any] = {"risk_score": risk_score}

        if confidence is not None:
            contributing_factors["confidence"] = confidence

        # 1. Primary policy reason
        if action == ACTION_ALLOW:
            reasons.append(f"Risk score {risk_score:.1f} within normal limits (0-{self.allow_max})")
        elif action == ACTION_MONITOR:
            reasons.append(f"Risk score {risk_score:.1f} reached MONITOR threshold ({self.monitor_min}-{self.monitor_max})")
        elif action == ACTION_RATE_LIMIT:
            reasons.append(f"Risk score {risk_score:.1f} reached RATE_LIMIT threshold ({self.rate_limit_min}-{self.rate_limit_max})")
        elif action == ACTION_BLOCK:
            reasons.append(f"Risk score {risk_score:.1f} reached BLOCK threshold (>={self.block_min})")

        # 2. Contextual indicators (only if explicitly present in context)
        # Upstream confirmation flag (if explicitly provided by Risk Engine)
        if context.get("is_confirmed_attack"):
            reasons.append("Confirmed attack pattern indicated by upstream risk engine")
            contributing_factors["is_confirmed_attack"] = True

        # Behavior model classification
        behavior_pred = context.get("behavior_prediction")
        if behavior_pred is not None:
            contributing_factors["behavior_prediction"] = behavior_pred
            if str(behavior_pred).lower() == "attacker":
                if confidence is not None:
                    reasons.append(f"Behavior ML classified session as attacker (confidence: {confidence:.1%})")
                else:
                    reasons.append("Behavior ML classified session as attacker")
            elif str(behavior_pred).lower() == "normal":
                if action == ACTION_ALLOW:
                    reasons.append("Behavior ML classified session as normal")

        # Authentication failure ratio (status 401 count / total)
        auth_ratio = context.get("auth_failure_ratio")
        if auth_ratio is not None and isinstance(auth_ratio, (int, float)):
            auth_val = float(auth_ratio)
            contributing_factors["auth_failure_ratio"] = auth_val
            if auth_val > 0.0:
                reasons.append(f"Authentication failure ratio elevated ({auth_val:.1%} of requests)")

        # Admin endpoint access count
        admin_probes = context.get("admin_endpoint_access")
        if admin_probes is not None and isinstance(admin_probes, (int, float)):
            admin_val = int(admin_probes)
            contributing_factors["admin_endpoint_access"] = admin_val
            if admin_val > 0:
                reasons.append(f"Sensitive/admin endpoint probe detected ({admin_val} request{'s' if admin_val > 1 else ''})")

        # Suspicious query keywords count (SQLi/XSS probes)
        query_kw = context.get("suspicious_query_keywords")
        if query_kw is not None and isinstance(query_kw, (int, float)):
            query_val = int(query_kw)
            contributing_factors["suspicious_query_keywords"] = query_val
            if query_val > 0:
                reasons.append(f"Suspicious query keyword pattern detected ({query_val} occurrence{'s' if query_val > 1 else ''})")

        # Burst request rate (max_requests_per_second)
        burst_rate = context.get("max_requests_per_second")
        if burst_rate is not None and isinstance(burst_rate, (int, float)):
            burst_val = int(burst_rate)
            contributing_factors["max_requests_per_second"] = burst_val
            if burst_val > 5:
                reasons.append(f"High request burst frequency detected ({burst_val} req/s)")

        # Repeated same endpoint
        repeated_ep = context.get("repeated_same_endpoint")
        if repeated_ep is not None and isinstance(repeated_ep, (int, float)):
            rep_val = int(repeated_ep)
            contributing_factors["repeated_same_endpoint"] = rep_val
            if rep_val > 10:
                reasons.append(f"High repetition on single endpoint ({rep_val} requests)")

        # Failed request ratio (4xx / 5xx)
        failed_ratio = context.get("failed_request_ratio")
        if failed_ratio is not None and isinstance(failed_ratio, (int, float)):
            failed_val = float(failed_ratio)
            contributing_factors["failed_request_ratio"] = failed_val
            if failed_val >= 0.3:
                reasons.append(f"Elevated request failure ratio ({failed_val:.1%} failed)")

        # Session request count
        req_count = context.get("request_count")
        if req_count is not None and isinstance(req_count, (int, float)):
            contributing_factors["request_count"] = int(req_count)

        # URL risk indicators
        url_risk = context.get("url_risk")
        if url_risk is not None:
            contributing_factors["url_risk"] = url_risk
            reasons.append(f"URL threat indicator flagged: {url_risk}")

        # Include other arbitrary context keys in contributing_factors safely
        for k, v in context.items():
            if k not in contributing_factors and isinstance(v, (str, int, float, bool)):
                contributing_factors[k] = v

        return reasons, contributing_factors

    def decide(
        self,
        risk_score: Union[float, int],
        confidence: Optional[float] = None,
        severity: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        timestamp: Optional[Union[datetime, str]] = None,
        db: Any = None,
        enforce_block: bool = False,
    ) -> dict[str, Any]:
        """
        Evaluate security context and return a structured SecurityDecision.
        """
        float_score, valid_confidence, valid_severity = self._validate_inputs(risk_score, confidence, severity)
        safe_context = context if isinstance(context, dict) else {}

        if timestamp is None:
            iso_timestamp = datetime.now(timezone.utc).isoformat()
        elif isinstance(timestamp, datetime):
            if timestamp.tzinfo is None:
                iso_timestamp = timestamp.replace(tzinfo=timezone.utc).isoformat()
            else:
                iso_timestamp = timestamp.isoformat()
        else:
            iso_timestamp = str(timestamp)

        if float_score <= self.allow_max:
            action = ACTION_ALLOW
        elif float_score <= self.monitor_max:
            action = ACTION_MONITOR
        elif float_score <= self.rate_limit_max:
            action = ACTION_RATE_LIMIT
        else:
            action = ACTION_BLOCK

        reasons, contributing_factors = self._build_reasons_and_factors(
            action=action,
            risk_score=float_score,
            confidence=valid_confidence,
            context=safe_context,
        )

        enforcement: dict[str, Any]

        if action == ACTION_RATE_LIMIT:
            enforcement = {
                "action": ACTION_RATE_LIMIT,
                "enforced": False,
                "mechanism": "none",
                "detail": "Rate limiting decision issued. Gateway rate limiter not configured in repository.",
            }

        elif action == ACTION_BLOCK:
            if enforce_block and db is not None and source_ip:
                try:
                    from app.blocking_service import block_ip

                    primary_reason = reasons[0] if reasons else "Adaptive agent block threshold reached"
                    behavior_pred = safe_context.get("behavior_prediction")

                    blocked_record = block_ip(
                        db=db,
                        ip=source_ip,
                        reason=primary_reason,
                        prediction=str(behavior_pred) if behavior_pred else None,
                        confidence=valid_confidence,
                        session_id=session_id,
                        url_score=safe_context.get("url_score"),
                        behavior_score=safe_context.get("behavior_score"),
                        risk_score=float_score,
                        severity=valid_severity,
                    )


                    blocked_until_iso = None
                    if hasattr(blocked_record, "blocked_until") and blocked_record.blocked_until:
                        b_until = blocked_record.blocked_until
                        if b_until.tzinfo is None:
                            b_until = b_until.replace(tzinfo=timezone.utc)
                        blocked_until_iso = b_until.isoformat()

                    enforcement = {
                        "action": ACTION_BLOCK,
                        "enforced": True,
                        "mechanism": "blocking_service.block_ip",
                        "blocked_until": blocked_until_iso,
                        "detail": "Active IP block enforced via blocking_service.",
                    }
                except Exception as exc:
                    enforcement = {
                        "action": ACTION_BLOCK,
                        "enforced": False,
                        "mechanism": "blocking_service.block_ip",
                        "detail": f"Failed to enforce block via blocking_service: {str(exc)}",
                    }
            else:
                enforcement = {
                    "action": ACTION_BLOCK,
                    "enforced": False,
                    "mechanism": "blocking_service.block_ip",
                    "detail": "Block decision issued. Live traffic enforcement hook available via enforce_block=True.",
                }

        elif action == ACTION_MONITOR:
            enforcement = {
                "action": ACTION_MONITOR,
                "enforced": True,
                "mechanism": "observability_log",
                "detail": "Session flagged for monitoring; no traffic interruption.",
            }

        else:
            enforcement = {
                "action": ACTION_ALLOW,
                "enforced": True,
                "mechanism": "pipeline_allow",
                "detail": "Request permitted through security pipeline.",
            }

        return {
            "action": action,
            "risk_score": float_score,
            "severity": valid_severity,
            "confidence": valid_confidence,
            "reasons": reasons,
            "contributing_factors": contributing_factors,
            "enforcement": enforcement,
            "session_id": session_id,
            "source_ip": source_ip,
            "timestamp": iso_timestamp,
        }


_default_agent = AdaptiveSecurityAgent()


def decide_adaptive_security(
    risk_score: Union[float, int],
    confidence: Optional[float] = None,
    severity: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
    session_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    timestamp: Optional[Union[datetime, str]] = None,
    db: Any = None,
    enforce_block: bool = False,
) -> dict[str, Any]:
    """
    Convenience function to evaluate a security decision using the default
    AdaptiveSecurityAgent configuration.
    """
    return _default_agent.decide(
        risk_score=risk_score,
        confidence=confidence,
        severity=severity,
        context=context,
        session_id=session_id,
        source_ip=source_ip,
        timestamp=timestamp,
        db=db,
        enforce_block=enforce_block,
    )
