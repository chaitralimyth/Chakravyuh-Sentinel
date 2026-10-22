"""Unit test for sqli_detector."""
import pytest
from app.sqli_detector import detect_sqli, canonicalize_input, inspect_payload_for_sqli


def test_sqli_detection_patterns():
    # Classical injection tautology
    r1 = detect_sqli("1' OR '1'='1")
    assert r1["is_sqli"] is True
    assert r1["confidence"] >= 0.95

    # Union select
    r2 = detect_sqli("UNION SELECT username, password FROM users")
    assert r2["is_sqli"] is True
    assert r2["confidence"] >= 0.95

    # Auth bypass
    r3 = detect_sqli("admin'--")
    assert r3["is_sqli"] is True

    # Encoded injection
    r4 = detect_sqli("%27%20OR%201%3D1--")
    assert r4["is_sqli"] is True

    # Stacked destructive query
    r5 = detect_sqli("1; DROP TABLE users--")
    assert r5["is_sqli"] is True

    # Time-based blind SQLi
    r6 = detect_sqli("1' AND SLEEP(5)--")
    assert r6["is_sqli"] is True

    # Metadata enumeration
    r7 = detect_sqli("1' UNION SELECT 1, sql FROM sqlite_master--")
    assert r7["is_sqli"] is True


def test_benign_text_not_flagged():
    # Benign natural text with SQL words
    b1 = detect_sqli("select a dress from the new collection")
    assert b1["is_sqli"] is False

    b2 = detect_sqli("please order by date ascending")
    assert b2["is_sqli"] is False

    b3 = detect_sqli("drop table tennis tournament update")
    assert b3["is_sqli"] is False

    b4 = detect_sqli("user login failed due to network timeout")
    assert b4["is_sqli"] is False

    b5 = detect_sqli("it's a beautiful morning")
    assert b5["is_sqli"] is False


def test_payload_inspection():
    payload = {
        "search": "summer dress",
        "nested": {
            "query": "1' OR '1'='1"
        }
    }
    res = inspect_payload_for_sqli(payload)
    assert res["is_sqli"] is True
