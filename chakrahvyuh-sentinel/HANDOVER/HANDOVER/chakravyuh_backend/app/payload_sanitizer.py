"""
Payload and Query Sanitizer for Chakravyuh Sentinel.

Provides:
1. Strict sensitive data redaction (passwords, tokens, credentials, cookies, api keys)
2. Safe investigation detail capture for URL query strings and JSON bodies
3. Safe ASGI request body inspection without consuming or corrupting downstream streams
4. Bounded storage representation (max 2,000 characters)
"""

import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple
from fastapi import Request

logger = logging.getLogger(__name__)

# Sensitive keys that must NEVER be persisted in plaintext
SENSITIVE_KEYS: Set[str] = {
    "password",
    "pass",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "api_key",
    "apikey",
    "key",
    "auth",
    "authorization",
    "bearer",
    "session",
    "session_id",
    "cookie",
    "credit_card",
    "card",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "pin",
    "account_number",
    "private_key",
    "credential",
    "credentials",
}


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key or parameter name indicates sensitive information."""
    if not isinstance(key, str):
        return False
    k = key.lower().replace("-", "_").replace(" ", "_").strip()
    return any(sensitive in k for sensitive in SENSITIVE_KEYS)


def redact_sensitive_data(data: Any, depth: int = 0, max_depth: int = 5) -> Any:
    """
    Recursively scans and redacts sensitive field values in dictionaries and lists.
    Preserves structural data, query terms, and attack evidence while stripping secrets.
    """
    if depth > max_depth:
        return "[MAX_DEPTH_REACHED]"

    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            str_key = str(k)
            if is_sensitive_key(str_key):
                redacted[str_key] = "[REDACTED]"
            else:
                redacted[str_key] = redact_sensitive_data(v, depth + 1, max_depth)
        return redacted

    elif isinstance(data, (list, tuple, set)):
        return [redact_sensitive_data(item, depth + 1, max_depth) for item in data]

    elif isinstance(data, str):
        # Truncate individual strings to prevent memory exhaustion
        if len(data) > 500:
            return data[:500] + "...[TRUNCATED]"
        return data

    return data


def sanitize_query_string(query_string: Optional[str]) -> str:
    """
    Sanitizes URL query string by redacting sensitive query parameter values
    while keeping safe parameter names and values intact for security audits.
    """
    if not query_string or not isinstance(query_string, str):
        return ""

    raw = query_string.strip()
    if raw.startswith("?"):
        raw = raw[1:]

    if not raw:
        return ""

    try:
        parsed = urllib.parse.parse_qsl(raw, keep_blank_values=True)
        sanitized_pairs = []
        for key, value in parsed:
            if is_sensitive_key(key):
                sanitized_pairs.append((key, "[REDACTED]"))
            else:
                # Keep up to 300 characters of safe value (e.g. search terms, SQLi signatures)
                sanitized_pairs.append((key, value[:300]))
        return urllib.parse.unquote(urllib.parse.urlencode(sanitized_pairs))
    except Exception:
        return "[SANITIZED_QUERY]"


def sanitize_json_text(raw_text: str) -> str:
    """Attempts to parse JSON text, redact sensitive fields, and serialize back."""
    if not raw_text or not isinstance(raw_text, str):
        return ""
    try:
        data = json.loads(raw_text)
        clean = redact_sensitive_data(data)
        return json.dumps(clean, ensure_ascii=False)
    except Exception:
        # If not JSON, truncate and return
        return raw_text[:500]


def build_evidence_string(
    query_string: Optional[str] = None,
    body_data: Optional[Any] = None,
    matched_pattern: Optional[str] = None,
    max_len: int = 2000,
) -> str:
    """
    Constructs a unified, bounded evidence string for investigation logs.
    """
    parts: List[str] = []

    clean_q = sanitize_query_string(query_string)
    if clean_q:
        parts.append(f"query: {clean_q}")

    if body_data is not None:
        if isinstance(body_data, (dict, list)):
            clean_b = redact_sensitive_data(body_data)
            try:
                parts.append(f"body: {json.dumps(clean_b, ensure_ascii=False)}")
            except Exception:
                parts.append(f"body: {str(clean_b)[:400]}")
        elif isinstance(body_data, str) and body_data.strip():
            clean_str = sanitize_json_text(body_data)
            parts.append(f"body: {clean_str}")

    if matched_pattern and matched_pattern not in " ".join(parts):
        parts.append(f"matched: {matched_pattern}")

    combined = " | ".join(parts)
    return combined[:max_len]


async def extract_and_sanitize_request(request: Request) -> Tuple[str, int]:
    """
    Safely inspects request URL query parameters and JSON body.
    Preserves ASGI receive stream so downstream route handlers and body parsers work normally.
    Returns:
        (sanitized_evidence_str, length)
    """
    query_str = request.url.query or ""
    body_obj = None

    content_type = request.headers.get("content-type", "").lower()

    if request.method in ("POST", "PUT", "PATCH"):
        # Safely capture JSON bodies
        if "application/json" in content_type:
            try:
                body_bytes = await request.body()
                if body_bytes:
                    request._body = body_bytes

                    body_consumed = False

                    async def receive():
                        nonlocal body_consumed
                        if not body_consumed:
                            body_consumed = True
                            return {"type": "http.request", "body": body_bytes, "more_body": False}
                        return {"type": "http.disconnect"}

                    request._receive = receive

                    try:
                        parsed = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                        body_obj = redact_sensitive_data(parsed)
                    except Exception:
                        body_obj = "[INVALID_JSON]"
            except Exception as e:
                logger.debug(f"Error reading request body for logging: {e}")
        elif "multipart/form-data" in content_type:
            body_obj = "[MULTIPART_FORM_DATA]"
        elif "application/octet-stream" in content_type:
            body_obj = "[BINARY_STREAM]"

    evidence = build_evidence_string(query_string=query_str, body_data=body_obj)
    return evidence, len(evidence)
