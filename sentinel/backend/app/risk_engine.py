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

def clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Keep a value between minimum and maximum."""
    return max(minimum, min(maximum, float(value)))

def calculate_request_rate_score(max_requests_per_second: float) -> float:
    """
    Convert requests-per-second into a 0-1 risk score.
    <= 2 requests/sec  -> low
    >= 20 requests/sec -> maximum
    """

    value = float(max_requests_per_second or 0)

    if value <= 2:
        return 0.0
    if value >= 20:
        return 1.0
    return (value - 2) / 18

def calculate_auth_failure_score(auth_failure_ratio: float) -> float:
    """Authentication failure ratio is already naturally 0-1."""
    return clamp(auth_failure_ratio)

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

def calculate_risk(
    url_attack_probability: float = 0.0,
    behavior_attack_probability: float = 0.0,
    request_rate_score: float = 0.0,
    auth_failure_score: float = 0.0,
    endpoint_risk_score: float = 0.0,
) -> dict:
    """
    Calculate final security risk.
    Weighting:
        URL threat          25%
        Behaviour threat    40%
        Request rate        15%
        Auth failures       10%
        Endpoint risk       10%
    """

    url_attack_probability = clamp(url_attack_probability)
    behavior_attack_probability = clamp(
        behavior_attack_probability
    )
    request_rate_score = clamp(request_rate_score)
    auth_failure_score = clamp(auth_failure_score)
    endpoint_risk_score = clamp(endpoint_risk_score)

    weighted_score = (
        0.25 * url_attack_probability
        + 0.40 * behavior_attack_probability
        + 0.15 * request_rate_score
        + 0.10 * auth_failure_score
        + 0.10 * endpoint_risk_score
    )

    risk_score = round(weighted_score * 100, 2)

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "components": {
            "url": round(url_attack_probability * 100, 2),
            "behavior": round(
                behavior_attack_probability * 100,
                2,
            ),
            "request_rate": round(
                request_rate_score * 100,
                2,
            ),
            "auth_failure": round(
                auth_failure_score * 100,
                2,
            ),
            "endpoint": round(
                endpoint_risk_score * 100,
                2,
            ),
        },
    }