"""
Chakravyuh Sentinel Risk Engine

Combines:
    - URL ML threat score
    - Behaviour ML threat score
    - Request-rate behaviour
    - Authentication failures
    - Endpoint sensitivity

into one normalized 0-100 security risk score.
"""

import math

def clamp(value: float, minimum: float = 0.0, maximum: float = 1.0, name: str = "value") -> float:
    """
    Keep a value between minimum and maximum.
    Explicitly rejects non-finite values (NaN, +Inf, -Inf) with ValueError.
    """
    if value is None:
        val = minimum
    else:
        try:
            val = float(value)
        except (TypeError, ValueError):
            val = minimum

    if math.isnan(val) or math.isinf(val):
        raise ValueError(f"{name} must be a finite real number, got {val}.")

    return max(minimum, min(maximum, val))

def calculate_request_rate_score(max_requests_per_second: float) -> float:
    """
    Convert requests-per-second into a 0-1 risk score.
    <= 2 requests/sec  -> low
    >= 20 requests/sec -> maximum
    Explicitly rejects non-finite values (NaN, +Inf, -Inf) with ValueError.
    """
    if max_requests_per_second is None:
        value = 0.0
    else:
        try:
            value = float(max_requests_per_second)
        except (TypeError, ValueError):
            value = 0.0

    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"max_requests_per_second must be a finite real number, got {value}.")

    if value <= 2.0:
        return 0.0
    if value >= 20.0:
        return 1.0
    return (value - 2.0) / 18.0

def calculate_auth_failure_score(auth_failure_ratio: float) -> float:
    """Authentication failure ratio is naturally 0-1."""
    return clamp(auth_failure_ratio, 0.0, 1.0, name="auth_failure_ratio")

def calculate_endpoint_risk(endpoint: str) -> float:
    """
    Contextual sensitivity score for the requested endpoint.
    """
    endpoint = (endpoint or "").lower()

    if "/admin" in endpoint:
        return 1.0
    if "/login" in endpoint:
        return 0.60
    if "/account" in endpoint:
        return 0.50
    if "/user" in endpoint:
        return 0.40

    return 0.10

def calculate_severity(risk_score: float) -> str:
    """
    Deterministically map a normalized risk score (0-100) to a severity label.
    Aligned with AdaptiveSecurityAgent action thresholds:
        0.0  <= R <= 29.0  -> LOW (ALLOW)
        29.0 <  R <= 59.0  -> MEDIUM (MONITOR)
        59.0 <  R <= 79.0  -> HIGH (RATE_LIMIT)
        79.0 <  R <= 100.0 -> CRITICAL (BLOCK)
    """
    if risk_score is None or isinstance(risk_score, bool):
        raise TypeError(f"risk_score must be a numeric value, got {type(risk_score).__name__}")
    try:
        val = float(risk_score)
    except (TypeError, ValueError):
        raise TypeError(f"risk_score must be a numeric value, got {type(risk_score).__name__}")

    if math.isnan(val) or math.isinf(val) or not (0.0 <= val <= 100.0):
        raise ValueError(f"risk_score must be a finite number in [0, 100], got {val}.")

    if val <= 29.0:
        return "LOW"
    elif val <= 59.0:
        return "MEDIUM"
    elif val <= 79.0:
        return "HIGH"
    else:
        return "CRITICAL"

def calculate_risk(
    url_attack_probability: float = 0.0,
    behavior_attack_probability: float = 0.0,
    request_rate_score: float = 0.0,
    auth_failure_score: float = 0.0,
    endpoint_risk_score: float = 0.0,
    sqli_score: float = 0.0,
) -> dict:
    """
    Calculate final security risk.
    Weighting:
        URL threat          25%
        Behaviour threat    40%
        Request rate        15%
        Auth failures       10%
        Endpoint risk       10%
    If an active SQL injection exploit is confirmed (sqli_score > 0),
    the composite risk score is elevated to ensure immediate critical policy intervention.
    Explicitly validates finite numbers and bounds output within [0.0, 100.0].
    """
    url_attack_probability = clamp(url_attack_probability, 0.0, 1.0, name="url_attack_probability")
    behavior_attack_probability = clamp(behavior_attack_probability, 0.0, 1.0, name="behavior_attack_probability")
    request_rate_score = clamp(request_rate_score, 0.0, 1.0, name="request_rate_score")
    auth_failure_score = clamp(auth_failure_score, 0.0, 1.0, name="auth_failure_score")
    endpoint_risk_score = clamp(endpoint_risk_score, 0.0, 1.0, name="endpoint_risk_score")
    sqli_score = clamp(sqli_score, 0.0, 1.0, name="sqli_score")

    weighted_score = (
        0.25 * url_attack_probability
        + 0.40 * behavior_attack_probability
        + 0.15 * request_rate_score
        + 0.10 * auth_failure_score
        + 0.10 * endpoint_risk_score
    )

    base_risk_score = round(weighted_score * 100, 2)
    risk_score = base_risk_score

    # Multi-vector elevation for behavioral attacks and volumetric bursts:
    # 1. Behavioral Burst Attack: If the behavior ML model classifies the session as an attacker
    #    (probability >= 0.8) and request velocity is high (request_rate_score >= 0.5),
    #    elevate into the CRITICAL BLOCK tier (>= 80.0, e.g. 85-99).
    # 2. Moderate Risk / Rate-Limit Tier: If request rate is elevated (request_rate_score >= 0.7)
    #    or behavior is suspicious (probability >= 0.6 and rate >= 0.3),
    #    elevate into the HIGH RATE_LIMIT tier (60.0 to 79.0).
    # 3. SQLi threat elevation: If confirmed SQL injection probe is detected, elevate to critical severity.
    if behavior_attack_probability >= 0.8 and request_rate_score >= 0.5:
        elevated = round(max(85.0, (0.5 * behavior_attack_probability + 0.5 * request_rate_score) * 100), 2)
        risk_score = max(risk_score, min(100.0, elevated))
    elif request_rate_score >= 0.7 or (behavior_attack_probability >= 0.6 and request_rate_score >= 0.3):
        elevated_rate = round((0.4 * max(behavior_attack_probability, 0.5) + 0.6 * request_rate_score) * 100, 2)
        bounded_elevated = max(60.0, min(79.0, elevated_rate))
        risk_score = max(risk_score, bounded_elevated)

    # If confirmed SQL injection probe is detected, elevate risk score to reflect critical severity
    if sqli_score > 0.0:
        risk_score = max(risk_score, round(sqli_score * 100, 2))

    risk_score = clamp(risk_score, 0.0, 100.0, name="risk_score")
    severity = calculate_severity(risk_score)

    components = {
        "url": round(url_attack_probability * 100, 2),
        "behavior": round(behavior_attack_probability * 100, 2),
        "request_rate": round(request_rate_score * 100, 2),
        "auth_failure": round(auth_failure_score * 100, 2),
        "endpoint": round(endpoint_risk_score * 100, 2),
    }
    if sqli_score > 0.0:
        components["sqli"] = round(sqli_score * 100, 2)

    return {
        "risk_score": risk_score,
        "severity": severity,
        "components": components,
    }
