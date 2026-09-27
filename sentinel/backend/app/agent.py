"""
Final Chakravyuh security decision agent.
The agent receives the combined risk score and contextual
security signals and decides:
    ALLOW
    MONITOR
    ALERT
    BLOCK
"""

def decide(
    risk_score: float,
    url: str = "",
    behavior_prediction: str | None = None,
    request_rate_score: float = 0.0,
    auth_failure_score: float = 0.0,
) -> tuple[str, list[str]]:

    reasons = []
    url_lower = (
        url or ""
    ).lower()

    # ---------------------------------------------------------
    # URL indicators
    # ---------------------------------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "bank",
        "paypal",
        "update",
        "confirm",
        "free",
        "gift",
        "win",
        "urgent",
    ]

    keyword_hits = sum(
        word in url_lower
        for word in suspicious_keywords
    )

    if keyword_hits >= 2:
        reasons.append(
            "Multiple suspicious URL keywords"
        )

    risky_tlds = [
        ".xyz",
        ".tk",
        ".ru",
        ".ml",
        ".ga",
        ".click",
    ]

    if any(
        tld in url_lower
        for tld in risky_tlds
    ):

        reasons.append(
            "Suspicious domain extension"
        )

    brands = [
        "google",
        "facebook",
        "amazon",
        "paypal",
        "bank",
    ]

    if (
        any(
            brand in url_lower
            for brand in brands
        )
        and keyword_hits >= 1
    ):

        reasons.append(
            "Possible brand impersonation"
        )

    # ---------------------------------------------------------
    # Behaviour indicators
    # ---------------------------------------------------------

    if behavior_prediction == "attacker":
        reasons.append(
            "Behaviour model classified session as attacker"
        )

    # ---------------------------------------------------------
    # Request rate
    # ---------------------------------------------------------

    if request_rate_score >= 0.8:
        reasons.append(
            "Abnormally high request rate"
        )

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    if auth_failure_score >= 0.5:
        reasons.append(
            "High authentication failure ratio"
        )

    # ---------------------------------------------------------
    # Final decision
    # ---------------------------------------------------------

    risk_score = float(risk_score)
    if risk_score >= 80:
        action = "BLOCK"

    elif risk_score >= 60:
        action = "ALERT"

    elif risk_score >= 30:
        action = "MONITOR"

    else:
        action = "ALLOW"

    if not reasons:
        reasons.append(
            "No significant threat indicators"
        )

    return action, reasons