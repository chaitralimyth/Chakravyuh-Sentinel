# Adaptive Security Agent — Chakravyuh Sentinel

## 1. Overview & Objective

The **Adaptive Security Agent** (`app.adaptive_agent`) is the deterministic decision-making layer of Chakravyuh Sentinel. It replaces naive binary blocking (`if malicious: block`) with a context-aware 4-tier security action policy:

$$\text{ALLOW} \quad\vert\quad \text{MONITOR} \quad\vert\quad \text{RATE\_LIMIT} \quad\vert\quad \text{BLOCK}$$

The agent is:
- **Deterministic**: Given identical inputs, it always produces identical actions, severities, and structured reasons.
- **Explainable**: Produces concrete, human-readable reasons for every decision without vague claims.
- **Side-Effect Free by Default**: Live enforcement hook (`enforce_block=False`) guarantees no accidental disruption to live traffic until explicitly enabled.
- **Honest on Enforcement**: Explicitly marks `RATE_LIMIT` as non-enforced because no rate-limiter gateway currently exists in the repository.
- **Resilient**: Gracefully handles missing or omitted optional context without crashing.

---

## 2. Architectural Placement

```
[ Incoming Request / External Traffic ]
                  │
                  ▼
         [ Session Builder ]
                  │
                  ▼
         [ Feature Extraction ]
                  │
                  ▼
        [ URL ML + Behavior ML ]
                  │
                  ▼
   [ Dynamic Risk Scoring Engine ] (Owned by Harshad)
                  │
                  ▼  normalized risk_score (0–100), confidence, context
    [ Adaptive Security Agent ] (app/adaptive_agent.py)
                  │
                  ▼  SecurityDecision (ALLOW / MONITOR / RATE_LIMIT / BLOCK)
    ┌─────────────┼─────────────────────────┐
    ▼             ▼                         ▼
[ Enforcement ] [ Security Alerts ] [ Incident Correlation & Timeline ]
(block_ip)       (Dashboard)         (Owned by Shrawan)
```

---

## 3. Decision Policy & Centralized Thresholds

The thresholds are centralized in `app/config.py` and can be overridden via environment variables without code modifications:

| Risk Score Range | Severity | Action | Policy Description | Enforcement Status |
| :---: | :---: | :---: | :--- | :--- |
| **0 – 29** | `LOW` | **`ALLOW`** | Normal request, no threat indicators. | Permitted through pipeline (`enforced: true`) |
| **30 – 59** | `MEDIUM` | **`MONITOR`** | Suspicious signals, heightened observation. | Logged with alert flag (`enforced: true`) |
| **60 – 79** | `HIGH` | **`RATE_LIMIT`** | Elevated risk pattern detected. | Throttling recommended (`enforced: false`, mechanism: none) |
| **80 – 100** | `CRITICAL` | **`BLOCK`** | Definite threat pattern detected. | Active IP block (`blocking_service.block_ip` when enabled) |

### Boundary Behavior:
- Exact bounds: `0` $\to$ ALLOW, `29` $\to$ ALLOW, `30` $\to$ MONITOR, `59` $\to$ MONITOR, `60` $\to$ RATE_LIMIT, `79` $\to$ RATE_LIMIT, `80` $\to$ BLOCK, `100` $\to$ BLOCK.
- Out of bounds (`< 0` or `> 100`): Raises `ValueError`.

---

## 4. Input Contract (For Harshad — Dynamic Risk Scoring Engine)

Harshad's Risk Engine can call the agent via the class or the convenience function:

```python
from app.adaptive_agent import decide_adaptive_security

decision = decide_adaptive_security(
    risk_score=normalized_score,    # Required: float or int between 0.0 and 100.0
    confidence=ml_confidence,       # Optional: float between 0.0 and 1.0 (or None)
    severity=severity_label,        # Optional: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" (or None)
    context=context_signals,        # Optional: dict of contextual signals
    session_id=session.session_id,  # Optional: str (or None)
    source_ip=session.ip,           # Optional: str (or None)
    timestamp=event_time,           # Optional: datetime or ISO-8601 str (or None)
    db=db,                          # Optional: SQLAlchemy session (default: None)
    enforce_block=False,            # Optional: bool (default: False)
)
```

### Contextual Signals Supported:
All contextual signals are drawn from **real** features already existing in the repository:
- `behavior_prediction`: `"attacker"` | `"normal"` (from `sentinel_behavior_model.pkl`)
- `auth_failure_ratio`: float (ratio of HTTP 401 statuses in the session)
- `admin_endpoint_access`: int (count of requests matching `/admin`)
- `suspicious_query_keywords`: int (count of SQLi/XSS keywords in query data)
- `max_requests_per_second`: int (peak request burst frequency)
- `repeated_same_endpoint`: int (maximum requests to any single endpoint)
- `failed_request_ratio`: float (ratio of HTTP 4xx/5xx responses)
- `request_count`: int (total requests in the session)
- `url_risk`: str or float (score or risk level from URL ML models)
- `is_confirmed_attack`: bool (optional upstream confirmation flag)

---

## 5. Output Contract (`SecurityDecision`)

The decision output is a JSON-serializable dictionary formatted for consumption by Incident Correlation, Explainability, and Admin Dashboards:

```json
{
  "action": "BLOCK",
  "risk_score": 85.0,
  "severity": "CRITICAL",
  "confidence": 0.92,
  "reasons": [
    "Risk score 85.0 reached BLOCK threshold (>=80)",
    "Behavior ML classified session as attacker (confidence: 92.0%)",
    "Authentication failure ratio elevated (40.0% of requests)",
    "Sensitive/admin endpoint probe detected (3 requests)"
  ],
  "contributing_factors": {
    "risk_score": 85.0,
    "confidence": 0.92,
    "behavior_prediction": "attacker",
    "auth_failure_ratio": 0.4,
    "admin_endpoint_access": 3
  },
  "enforcement": {
    "action": "BLOCK",
    "enforced": false,
    "mechanism": "blocking_service.block_ip",
    "detail": "Block decision issued. Live traffic enforcement hook available via enforce_block=True."
  },
  "session_id": "d261bfc44942465f8a5f3312734be21e",
  "source_ip": "192.168.1.100",
  "timestamp": "2026-09-27T16:30:00+00:00"
}
```

---

## 6. Explainability Principles

- **Primary reason**: Reflects the deterministic threshold mapping.
- **Specific context reasons**: Only added when positive contextual indicators exist in `context`.
- **Conservative wording**: Does not claim "confirmed attack" solely because the numeric threshold was crossed. Uses "Risk score X reached BLOCK threshold (>=80)" unless the upstream risk engine explicitly supplied `is_confirmed_attack=True`.

---

## 7. Integration Guide for Teammates

### For Harshad (Dynamic Risk Scoring Engine):
1. Compute your normalized composite risk score ($0.0 \le \text{risk\_score} \le 100.0$) using your formula combining URL ML and Behavior ML.
2. Call `decide_adaptive_security(risk_score=..., confidence=..., context=...)`.
3. You do not need to implement decision thresholds or action mapping in your engine; the Adaptive Agent handles all policy determination and explanation.

### For Shrawan (Incident Correlation & Attack Timeline):
1. The `SecurityDecision` output dictionary provides all fields required for incident creation:
   - Group by `session_id` to build session-level attack timelines.
   - Aggregate by `source_ip` to identify persistent threat actors.
   - Use `reasons` directly as human-readable incident summaries in the dashboard.
   - Use `contributing_factors` to correlate multiple attack vectors (e.g. auth brute forcing + admin probing).

### For Live Pipeline Integration:
When ready to connect the agent to live requests (e.g. in `app/main.py` or middleware):
```python
decision = decide_adaptive_security(
    risk_score=risk_score,
    confidence=confidence,
    context=feature_context,
    session_id=session.session_id,
    source_ip=client_ip,
    db=db,
    enforce_block=True,  # Activates automatic IP blocking in DB
)
```

---

## 8. Limitations & Future Work
- **Rate Limiting**: Currently a decision-only signal. Real enforcement requires integration with an API gateway (e.g., Redis token bucket or Nginx limit_req).
- **Dynamic Threshold Learning**: The current policy is strictly deterministic based on static thresholds. Dynamic adjustment based on baseline false positive rates can be introduced in future iterations.
