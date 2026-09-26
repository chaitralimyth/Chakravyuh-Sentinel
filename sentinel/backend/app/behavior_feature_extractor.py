"""
Builds the 28-value behavior feature vector for a session, using ONLY real
request data pulled from request_logs (no random/fake values).

*** IMPORTANT — READ BEFORE TRUSTING PREDICTIONS ***
You gave me the 28 FEATURE NAMES (from feature_columns_behaviour.pkl) but not
the original feature-engineering script used to build the training data.
The exact definitions below (e.g. what counts as "admin_endpoint_access",
what counts as a "suspicious query keyword", how "repeated_same_endpoint" is
computed) are my best-effort, clearly-documented reconstruction — not
verified against your training pipeline. If these definitions don't match
how the training set was built, the model will still run, but its
predictions will be unreliable, because it will be scored on a different
feature distribution than it was trained on.

Before relying on this in production, compare each function below against
whatever notebook/script generated your training CSV and adjust as needed.
"""

import math
from collections import Counter
from datetime import datetime

from sqlalchemy.orm import Session as DBSession

from app.db_models import RequestLog
from app.behavior_model_loader import behavior_feature_order

# Assumption: substrings considered "admin" endpoints. Adjust to match
# your actual route naming if different (e.g. "/dashboard/admin").
ADMIN_ENDPOINT_MARKERS = ("/admin",)

# Assumption: crude suspicious-query keyword list (SQLi / XSS-style probes).
# Replace with whatever list your training data generation used, if different.
SUSPICIOUS_QUERY_KEYWORDS = (
    "select ", "union ", "drop table", "--", "' or ", "\" or ",
    "<script", "onerror=", "../", "xp_cmdshell", "1=1",
)


def _shannon_entropy(counts: list) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def _max_requests_per_second(timestamps: list) -> int:
    if not timestamps:
        return 0
    buckets = Counter(ts.replace(microsecond=0) for ts in timestamps)
    return max(buckets.values())


def build_feature_dict(rows: list[RequestLog]) -> dict:
    """rows: RequestLog objects for one session, ordered by timestamp ascending."""

    n = len(rows)
    if n == 0:
        return {name: 0 for name in behavior_feature_order}

    methods = [r.method.upper() for r in rows]
    statuses = [r.status_code for r in rows]
    endpoints = [r.endpoint for r in rows]
    timestamps = [r.timestamp for r in rows]
    query_lengths = [r.query_length or 0 for r in rows]
    request_sizes = [r.request_size or 0 for r in rows]
    response_sizes = [r.response_size or 0 for r in rows]
    response_times = [r.response_time_ms or 0.0 for r in rows]

    method_counts = Counter(methods)
    status_counts = Counter(statuses)
    endpoint_counts = Counter(endpoints)

    status_200_count = status_counts.get(200, 0)
    status_400_count = status_counts.get(400, 0)
    status_401_count = status_counts.get(401, 0)
    status_422_count = status_counts.get(422, 0)

    admin_endpoint_access = sum(
        1 for e in endpoints if any(m in e.lower() for m in ADMIN_ENDPOINT_MARKERS)
    )

    suspicious_query_keywords = sum(
        1
        for r in rows
        if r.query_data and any(k in r.query_data.lower() for k in SUSPICIOUS_QUERY_KEYWORDS)
    )

    repeated_same_endpoint = max(endpoint_counts.values()) if endpoint_counts else 0

    if n > 1:
        intervals = [
            (timestamps[i] - timestamps[i - 1]).total_seconds() for i in range(1, n)
        ]
        average_interval_between_requests = sum(intervals) / len(intervals)
    else:
        average_interval_between_requests = 0.0

    failed_count = status_400_count + status_401_count + status_422_count

    endpoint_switches = sum(
        1 for i in range(1, n) if endpoints[i] != endpoints[i - 1]
    )
    endpoint_switch_rate = endpoint_switches / (n - 1) if n > 1 else 0.0

    session_duration_seconds = (
        (timestamps[-1] - timestamps[0]).total_seconds() if n > 1 else 0.0
    )

    features = {
        "request_count": n,
        "get_count": method_counts.get("GET", 0),
        "post_count": method_counts.get("POST", 0),
        "put_count": method_counts.get("PUT", 0),
        "patch_count": method_counts.get("PATCH", 0),
        "delete_count": method_counts.get("DELETE", 0),
        "status_200_count": status_200_count,
        "status_400_count": status_400_count,
        "status_401_count": status_401_count,
        "status_422_count": status_422_count,
        "unique_endpoints": len(endpoint_counts),
        "admin_endpoint_access": admin_endpoint_access,
        "suspicious_query_keywords": suspicious_query_keywords,
        "repeated_same_endpoint": repeated_same_endpoint,
        "average_interval_between_requests": average_interval_between_requests,
        "average_response_time_ms": sum(response_times) / n,
        "average_request_size": sum(request_sizes) / n,
        "average_response_size": sum(response_sizes) / n,
        "auth_failure_ratio": status_401_count / n,
        "failed_request_ratio": failed_count / n,
        "success_request_ratio": status_200_count / n,
        "endpoint_entropy": _shannon_entropy(list(endpoint_counts.values())),
        "max_requests_per_second": _max_requests_per_second(timestamps),
        "unique_methods": len(method_counts),
        "mean_query_length": sum(query_lengths) / n,
        "max_query_length": max(query_lengths),
        "endpoint_switch_rate": endpoint_switch_rate,
        "session_duration_seconds": session_duration_seconds,
    }

    return features


def build_feature_vector(rows: list[RequestLog]) -> list:
    """Returns the 28 values in the EXACT order from feature_columns_behaviour.pkl."""
    features = build_feature_dict(rows)
    return [features[name] for name in behavior_feature_order]
