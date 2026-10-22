"""
High-Precision SQL Injection (SQLi) Detection Engine for Chakravyuh Sentinel.

Provides:
1. Recursive canonicalization (multi-layer URL decoding, hex/unicode unescaping, whitespace collapsing)
2. Grammar and pattern-based signature detection for SQL injection attack vectors
3. Distinction between natural-language text containing SQL keywords vs active injection syntax
4. Standardized structured output with confidence and risk score
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


def canonicalize_input(raw: str, max_rounds: int = 3) -> str:
    """
    Recursively decodes URL encoding, Unicode escapes, and hex notations.
    Normalizes whitespace and removes SQL inline comments used for obfuscation.
    """
    if not isinstance(raw, str):
        return str(raw)

    current = raw
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded

    # Unescape unicode escapes like \u0027 -> '
    try:
        current = current.encode("utf-8").decode("unicode_escape")
    except Exception:
        pass

    # Replace inline SQL comments used to break tokens: e.g. SEL/**/ECT -> SELECT
    cleaned = re.sub(r"/\*.*?\*/", " ", current)

    # Normalize multiple whitespace characters
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned


# Strict regex patterns representing confirmed SQL injection attack signatures
SQLI_SIGNATURES: List[Tuple[str, str, float]] = [
    # 1. Classical Tautologies / Boolean-based bypass
    (
        r"(?i)(?:'|\"|\b)\s*(?:or|and)\s+['\"]?[a-zA-Z0-9_]+['\"]?\s*=\s*['\"]?[a-zA-Z0-9_]+",
        "SQL boolean tautology (e.g. ' OR '1'='1' or 1=1)",
        0.98,
    ),
    (
        r"(?i)(?:'|\"|\b)\s*(?:or|and)\s+(?:true|false|\d+)\s*(?:--|#|/\*)",
        "SQL boolean tautology with trailing comment",
        0.99,
    ),
    (
        r"(?i)(?:'|\")\s*(?:or|and)\s*['\"]['\"]\s*=\s*['\"]",
        "SQL empty string tautology (' OR ''=')",
        0.98,
    ),
    (
        r"(?i)admin['\"]\s*(?:--|#|/\*)",
        "SQL authentication comment bypass (admin'--)",
        0.99,
    ),
    # 2. UNION-based Injections
    (
        r"(?i)\bunion\s+(?:all\s+)?select\b",
        "SQL UNION SELECT extraction payload",
        0.99,
    ),
    # 3. Stacked / Piggybacked Queries
    (
        r"(?i);\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|truncate\s+table|alter\s+table)\b",
        "SQL stacked destructive query (; DROP/DELETE/INSERT/UPDATE)",
        0.99,
    ),
    (
        r"(?i);\s*(?:exec|execute)\s*\(",
        "SQL stacked command execution (; EXEC)",
        0.99,
    ),
    # 4. Comment-terminated Injection Probes
    (
        r"(?i)['\"](?:\s*;\s*|\s+)(?:--|#|/\*)",
        "SQL quote termination with comment delimiter ('--)",
        0.95,
    ),
    (
        r"(?i)\b(?:select|union|having|where)\b.*(?:--|#)",
        "SQL keyword sequence terminated with comment",
        0.95,
    ),
    # 5. Time-based Blind SQLi functions
    (
        r"(?i)\b(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",
        "Time-based blind SQL injection function",
        0.99,
    ),
    # 6. Database Metadata / Schema Enumeration
    (
        r"(?i)\b(?:information_schema|sqlite_master|sys\.tables|sqlite_temp_master)\b",
        "Database schema metadata enumeration probe",
        0.95,
    ),
    # 7. Out-of-band / File I/O functions
    (
        r"(?i)\b(?:load_file|into\s+outfile|into\s+dumpfile)\b",
        "SQL file reading or writing primitive",
        0.99,
    ),
    # 8. Error-based XPath / XML probes
    (
        r"(?i)\b(?:extractvalue|updatexml)\s*\(",
        "SQL error-based XML extraction probe",
        0.98,
    ),
]


def detect_sqli(text: Optional[str]) -> Dict[str, Any]:
    """
    Evaluates text for SQL injection payloads.
    Returns structured results:
    {
        "is_sqli": bool,
        "confidence": float,
        "risk_score": float,
        "matched_patterns": list[str],
        "canonical_text": str
    }
    """
    if not text or not isinstance(text, str):
        return {
            "is_sqli": False,
            "confidence": 0.0,
            "risk_score": 0.0,
            "matched_patterns": [],
            "canonical_text": "",
        }

    canonical = canonicalize_input(text)

    # Empty string after normalization
    if not canonical:
        return {
            "is_sqli": False,
            "confidence": 0.0,
            "risk_score": 0.0,
            "matched_patterns": [],
            "canonical_text": "",
        }

    matched_patterns = []
    max_confidence = 0.0

    for pattern, description, confidence in SQLI_SIGNATURES:
        if re.search(pattern, canonical):
            matched_patterns.append(description)
            if confidence > max_confidence:
                max_confidence = confidence

    # Check for benign false positive mitigations:
    # If standard English sentence without quotes/syntax:
    # e.g. "select products from our summer collection"
    # Although it contains "select" and "from", it lacks quotes, semicolons, comments, or operators
    is_sqli = len(matched_patterns) > 0

    risk_score = round(max_confidence * 100.0, 2) if is_sqli else 0.0

    return {
        "is_sqli": is_sqli,
        "confidence": max_confidence,
        "risk_score": risk_score,
        "matched_patterns": matched_patterns,
        "canonical_text": canonical[:200],
    }


def inspect_payload_for_sqli(data: Any) -> Dict[str, Any]:
    """
    Recursively scans strings, dictionaries, lists, and query parameters
    for SQL injection patterns.
    """
    if isinstance(data, str):
        return detect_sqli(data)
    elif isinstance(data, dict):
        all_matches = []
        max_conf = 0.0
        for k, v in data.items():
            # Check key
            k_res = inspect_payload_for_sqli(k)
            if k_res["is_sqli"]:
                all_matches.extend(k_res["matched_patterns"])
                max_conf = max(max_conf, k_res["confidence"])
            # Check value
            v_res = inspect_payload_for_sqli(v)
            if v_res["is_sqli"]:
                all_matches.extend(v_res["matched_patterns"])
                max_conf = max(max_conf, v_res["confidence"])

        is_sqli = len(all_matches) > 0
        return {
            "is_sqli": is_sqli,
            "confidence": max_conf,
            "risk_score": round(max_conf * 100.0, 2) if is_sqli else 0.0,
            "matched_patterns": list(set(all_matches)),
            "canonical_text": "",
        }
    elif isinstance(data, (list, tuple, set)):
        all_matches = []
        max_conf = 0.0
        for item in data:
            item_res = inspect_payload_for_sqli(item)
            if item_res["is_sqli"]:
                all_matches.extend(item_res["matched_patterns"])
                max_conf = max(max_conf, item_res["confidence"])

        is_sqli = len(all_matches) > 0
        return {
            "is_sqli": is_sqli,
            "confidence": max_conf,
            "risk_score": round(max_conf * 100.0, 2) if is_sqli else 0.0,
            "matched_patterns": list(set(all_matches)),
            "canonical_text": "",
        }

    return {
        "is_sqli": False,
        "confidence": 0.0,
        "risk_score": 0.0,
        "matched_patterns": [],
        "canonical_text": "",
    }
