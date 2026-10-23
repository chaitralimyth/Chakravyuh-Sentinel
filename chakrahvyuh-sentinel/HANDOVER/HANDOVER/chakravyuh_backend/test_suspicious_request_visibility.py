"""
Comprehensive test suite for Suspicious Request Visibility and Blocked-IP Investigation Details
in Chakravyuh Sentinel.

Covers:
1. URL query capture and safe parameter visibility.
2. Safe JSON-body capture without downstream handler interruption.
3. Strict sensitive data redaction (passwords, tokens, keys, cookies, card numbers).
4. SQL-injection attack evidence capture and correlation with BlockedIP records.
5. Fallback behavior when triggering request details are unavailable (no fabrication).
6. Block and unblock lifecycle preservation.
7. Query evidence length bounding (max 2,000 characters).
"""

import json
import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal, init_db
from app.db_models import BlockedIP, RequestLog, SecurityAlert
from app.blocking_service import block_ip
from app.payload_sanitizer import (
    is_sensitive_key,
    redact_sensitive_data,
    sanitize_query_string,
    sanitize_json_text,
    build_evidence_string,
)


class TestSuspiciousRequestVisibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def test_sensitive_key_detection(self):
        """Verify sensitive keywords are correctly recognized."""
        self.assertTrue(is_sensitive_key("password"))
        self.assertTrue(is_sensitive_key("current_password"))
        self.assertTrue(is_sensitive_key("access_token"))
        self.assertTrue(is_sensitive_key("Authorization"))
        self.assertTrue(is_sensitive_key("api_key"))
        self.assertTrue(is_sensitive_key("client_secret"))
        self.assertTrue(is_sensitive_key("cookie"))
        self.assertTrue(is_sensitive_key("card_number"))
        self.assertTrue(is_sensitive_key("cvv"))

        # Non-sensitive keys should not be flagged
        self.assertFalse(is_sensitive_key("search"))
        self.assertFalse(is_sensitive_key("q"))
        self.assertFalse(is_sensitive_key("username"))
        self.assertFalse(is_sensitive_key("category"))
        self.assertFalse(is_sensitive_key("limit"))

    def test_recursive_sensitive_data_redaction(self):
        """Verify nested structures have secrets scrubbed while safe fields remain."""
        raw_payload = {
            "search_term": "facial treatments",
            "user_id": 42,
            "credentials": {
                "password": "SuperSecretPassword123!",
                "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            },
            "user_profile": {
                "password": "NestedPassword456!",
                "nickname": "glam_user",
            },
            "payment": {
                "card_number": "4111222233334444",
                "cvv": "123",
                "amount": 99.50,
            },
            "meta": ["safe_tag", {"api_key": "secret_key_abcdef"}],
        }

        redacted = redact_sensitive_data(raw_payload)

        # Secrets must be removed
        self.assertNotIn("SuperSecretPassword123!", str(redacted))
        self.assertNotIn("NestedPassword456!", str(redacted))
        self.assertNotIn("4111222233334444", str(redacted))
        self.assertNotIn("secret_key_abcdef", str(redacted))

        # Safe values must be preserved
        self.assertEqual(redacted["search_term"], "facial treatments")
        self.assertEqual(redacted["user_id"], 42)
        self.assertEqual(redacted["payment"]["amount"], 99.50)
        self.assertEqual(redacted["user_profile"]["nickname"], "glam_user")
        self.assertEqual(redacted["user_profile"]["password"], "[REDACTED]")
        self.assertEqual(redacted["credentials"], "[REDACTED]")
        self.assertEqual(redacted["payment"]["card_number"], "[REDACTED]")
        self.assertEqual(redacted["meta"][1]["api_key"], "[REDACTED]")

    def test_query_string_sanitization(self):
        """Verify URL query parameter values are sanitized without losing investigation context."""
        query = "category=skincare&q=' UNION SELECT 1,2,3--&password=MyPlaintextPass!&token=xyz789"
        sanitized = sanitize_query_string(query)

        self.assertNotIn("MyPlaintextPass!", sanitized)
        self.assertNotIn("xyz789", sanitized)
        self.assertIn("password=[REDACTED]", sanitized)
        self.assertIn("token=[REDACTED]", sanitized)
        self.assertIn("category=skincare", sanitized)
        self.assertIn("UNION", sanitized)  # SQL injection test signature preserved for SOC analysis

    def test_url_query_capture_in_request_log(self):
        """A request containing test query parameters is visible in /requests with safe parameters."""
        test_ip = "192.0.2.10"
        headers = {"X-Forwarded-For": test_ip}

        # Issue GET request with query params to an exempt/monitoring route
        resp = self.client.get(
            "/stats?search=spa_massage&password=LeakedSecretPassword!",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        # Retrieve request log from Sentinel
        log_resp = self.client.get(f"/requests?ip={test_ip}&source_site=sentinel&limit=5")
        self.assertEqual(log_resp.status_code, 200)
        logs = log_resp.json()
        self.assertGreater(len(logs), 0)

        latest = logs[0]
        self.assertEqual(latest["ip"], test_ip)
        self.assertIn("search=spa_massage", latest["query_data"])
        # Password must be redacted
        self.assertNotIn("LeakedSecretPassword!", latest["query_data"])
        self.assertIn("[REDACTED]", latest["query_data"])

    def test_safe_json_body_capture_without_breaking_downstream(self):
        """JSON requests with safe test fields are captured without breaking downstream processing."""
        test_ip = "192.0.2.20"
        payload = {
            "ip": test_ip,
            "source_site": "x-beauty",
            "method": "POST",
            "endpoint": "/api/bookings/search",
            "status_code": 200,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query_data": '{"service": "hydra-facial", "notes": "first time customer", "token": "secret_session_token_123"}',
        }

        # Send to ingest-traffic
        resp = self.client.post("/api/ingest-traffic", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))

        # Verify in /requests
        req_resp = self.client.get(f"/requests?ip={test_ip}&source_site=x-beauty")
        self.assertEqual(req_resp.status_code, 200)
        items = req_resp.json()
        self.assertGreater(len(items), 0)
        latest = items[0]

        # Check evidence captured and secrets stripped
        self.assertIn("hydra-facial", latest["query_data"])
        self.assertIn("first time customer", latest["query_data"])
        self.assertNotIn("secret_session_token_123", latest["query_data"])
        self.assertIn("[REDACTED]", latest["query_data"])

    def test_sqli_attack_evidence_linked_to_blocked_ip(self):
        """SQL injection attempts produce a blocked IP with linked triggering request evidence."""
        attacker_ip = "198.51.100.88"
        headers = {"X-Forwarded-For": attacker_ip}

        # Send SQLi payload via query param
        attack_url = "/services?q=' OR '1'='1 --"
        resp = self.client.get(attack_url, headers=headers)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json().get("action"), "BLOCK")

        # Verify block record contains triggering request evidence
        blocks_resp = self.client.get("/blocked-ips?active_only=true")
        self.assertEqual(blocks_resp.status_code, 200)
        blocks = blocks_resp.json()
        attacker_block = next((b for b in blocks if b["ip"] == attacker_ip), None)
        self.assertIsNotNone(attacker_block, "Attacker IP not found in active blocks")

        # Check triggering request is linked
        tr = attacker_block.get("triggering_request")
        self.assertIsNotNone(tr, "Triggering request was not linked to block")
        self.assertEqual(tr["method"], "GET")
        self.assertEqual(tr["status_code"], 403)
        self.assertIn("/services", tr["endpoint"])
        self.assertIn("OR '1'='1", tr["query_data"])

        # Also verify dedicated evidence endpoint
        ev_resp = self.client.get(f"/blocked-ips/{attacker_block['id']}/evidence")
        self.assertEqual(ev_resp.status_code, 200)
        ev_data = ev_resp.json()
        self.assertIsNotNone(ev_data.get("triggering_request"))
        self.assertEqual(ev_data["triggering_request"]["status_code"], 403)

    def test_block_without_request_returns_none_evidence(self):
        """Blocks without any recorded request explicitly return None triggering_request."""
        admin_blocked_ip = "203.0.113.99"

        # Create block directly in DB with no request logs
        block_ip(
            db=self.db,
            ip=admin_blocked_ip,
            reason="Manual policy enforcement by SOC administrator",
            prediction="attacker",
            confidence=1.0,
            risk_score=95.0,
            severity="HIGH",
        )

        blocks_resp = self.client.get("/blocked-ips?active_only=true")
        self.assertEqual(blocks_resp.status_code, 200)
        blocks = blocks_resp.json()
        record = next((b for b in blocks if b["ip"] == admin_blocked_ip), None)
        self.assertIsNotNone(record)

        # Must explicitly be None rather than fabricated data
        self.assertIsNone(record.get("triggering_request"))

        # Dedicated endpoint also returns None
        ev_resp = self.client.get(f"/blocked-ips/{record['id']}/evidence")
        self.assertEqual(ev_resp.status_code, 200)
        self.assertIsNone(ev_resp.json().get("triggering_request"))

    def test_unblock_lifecycle_preserved(self):
        """Unblocking an IP restores access and preserves normal operation."""
        test_ip = "198.51.100.95"
        headers = {"X-Forwarded-For": test_ip}

        # Block the IP
        block_ip(db=self.db, ip=test_ip, reason="Temporary block test")

        # Verify 403 on protected route
        r1 = self.client.get("/some-protected-endpoint", headers=headers)
        self.assertEqual(r1.status_code, 403)

        # Unblock via Sentinel API
        unblock_resp = self.client.post("/api/unblock-ip", json={"ip": test_ip})
        self.assertEqual(unblock_resp.status_code, 200)
        self.assertTrue(unblock_resp.json().get("success"))

        # Verify block is no longer active
        blocks_resp = self.client.get("/blocked-ips?active_only=true")
        active_ips = [b["ip"] for b in blocks_resp.json()]
        self.assertNotIn(test_ip, active_ips)

    def test_evidence_bounding_length(self):
        """Combined query and body evidence is strictly bounded to 2,000 characters."""
        long_param = "a" * 1500
        long_body = {"key": "b" * 1500}
        evidence = build_evidence_string(query_string=f"param={long_param}", body_data=long_body)
        self.assertLessEqual(len(evidence), 2000)


if __name__ == "__main__":
    unittest.main()
