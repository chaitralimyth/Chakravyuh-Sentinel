"""
Chakravyuh Sentinel Incident Explanation Service

Generates deterministic human-readable explanations of why an incident was created
based on associated security alerts and signals.
"""

def generate_incident_explanation(incident, alerts) -> dict:
    """
    Generates a deterministic human-readable explanation
    of why an incident was created.
    """
    if not alerts:
        return {
            "title": "Security Incident",
            "summary": "No security alerts are associated with this incident.",
            "risk_score": getattr(incident, "risk_score", 0.0),
            "severity": getattr(incident, "severity", "LOW"),
            "action": getattr(incident, "primary_action", "MONITOR"),
            "factors": [],
        }

    factors = []

    max_url_score = max([(a.url_score or 0.0) for a in alerts], default=0.0)
    max_behavior_score = max([(a.behavior_score or 0.0) for a in alerts], default=0.0)
    max_risk_score = max([(a.risk_score or 0.0) for a in alerts], default=0.0)

    predictions = [str(a.prediction).lower() for a in alerts if a.prediction]
    actions = [str(a.action).upper() for a in alerts if a.action]

    if max_url_score >= 0.7:
        factors.append("The URL analysis produced a high maliciousness score.")

    if max_behavior_score >= 0.7:
        factors.append("The user's behaviour was classified as suspicious.")

    if "attacker" in predictions:
        factors.append("The behaviour model classified the activity as attacker-like.")

    if "BLOCK" in actions:
        factors.append("The security agent blocked the source IP.")

    if "RATE_LIMIT" in actions:
        factors.append("The security agent recommended rate-limiting the source IP.")

    if "ALERT" in actions:
        factors.append("The security agent generated a security alert.")

    if "MONITOR" in actions and "BLOCK" not in actions:
        factors.append("The security agent placed the session under heightened monitoring.")

    if not factors:
        factors.append("Multiple security signals contributed to this incident.")

    summary = (
        f"This incident contains {len(alerts)} security event(s). "
        f"The highest observed risk score was {max_risk_score:.2f}/100. "
        f"The incident severity is {incident.severity} "
        f"and the primary action is {incident.primary_action}."
    )

    return {
        "title": "Chakravyuh Sentinel Security Incident",
        "summary": summary,
        "risk_score": max_risk_score,
        "severity": incident.severity,
        "action": incident.primary_action,
        "factors": factors,
    }
