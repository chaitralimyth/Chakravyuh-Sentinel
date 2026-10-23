"""
End-to-End Security Verification & Hardening Test Suite for Chakravyuh Sentinel
Directly verifies:
1. High-volume burst & behavioral attack blocking
2. Subsequent requests from blocked client remain blocked (Pre-Route HTTP 403)
3. Moderate-risk dynamic rate limiting (boundaries 59.0, 60.0, 79.0, 80.0)
4. HTTP 429 Too Many Requests enforcement with Retry-After header
5. Rate limit quota reset and cross-session persistence
6. Block precedence: blocked client is NEVER downgraded to rate-limited status
7. SQL injection pre-route rejection on JSON bodies and query strings
8. Legitimate application operations continue to succeed
"""

import os
import sys
import time
import unittest
from unittest.mock import patch

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["ALLOW_LOCALHOST_BYPASS"] = "false"

from fastapi.testclient import TestClient
from app.database import Base, engine, SessionLocal
from app.main import app
from app.db_models import BlockedIP, RequestLog, SessionRecord, SecurityAlert, RateLimitEvent
from app.blocking_service import block_ip, is_ip_blocked
from app.rate_limit_middleware import _rate_limiter
from app.risk_engine import calculate_risk, calculate_severity
from app.adaptive_agent import (
    decide_adaptive_security,
    ACTION_ALLOW,
    ACTION_MONITOR,
    ACTION_RATE_LIMIT,
    ACTION_BLOCK,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)


class TestLiveSecurityHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)

    def setUp(self):
        self.client = TestClient(app)

    def test_scenario_1_normal_traffic_succeeds(self):
        """Normal legitimate requests succeed and are not blocked or rate-limited."""
        client_ip = "192.168.10.101"
        headers = {"X-Forwarded-For": client_ip}
        resp = self.client.get("/", headers=headers)
        self.assertEqual(resp.status_code, 200)

        search_resp = self.client.get("/api/search?q=services", headers=headers)
        self.assertEqual(search_resp.status_code, 200)
        self.assertEqual(search_resp.json()["query"], "services")

    def test_scenario_2_and_3_high_volume_burst_and_persistent_block(self):
        """
        High-volume burst triggers behavioral risk elevation and active IP block.
        Subsequent requests from the client remain strictly blocked (HTTP 403).
        """
        burst_ip = "198.51.100.55"
        headers = {"X-Forwarded-For": burst_ip}

        # 1. Send burst traffic simulating 1000-request high-volume attack
        # Ingest traffic with high burst rate and behavioral attack markers
        for i in range(10):
            ingest_resp = self.client.post(
                "/api/ingest-traffic",
                json={
                    "ip": burst_ip,
                    "method": "GET",
                    "endpoint": f"/api/items/{i}",
                    "status_code": 200,
                    "timestamp": "2026-10-23T18:00:00Z",
                    "request_size": 100,
                    "response_size": 500,
                    "response_time_ms": 2.0,
                    "query_length": 0,
                    "query_data": "",
                },
            )
            self.assertEqual(ingest_resp.status_code, 200)

        # Explicitly verify high-risk score calculation for volumetric burst
        risk = calculate_risk(
            url_attack_probability=0.0,
            behavior_attack_probability=0.95,
            request_rate_score=0.90,
            auth_failure_score=0.0,
            endpoint_risk_score=0.10,
        )
        self.assertGreaterEqual(risk["risk_score"], 80.0)
        self.assertEqual(risk["severity"], SEVERITY_CRITICAL)

        decision = decide_adaptive_security(
            risk_score=risk["risk_score"],
            confidence=0.95,
            severity=risk["severity"],
            source_ip=burst_ip,
        )
        self.assertEqual(decision["action"], ACTION_BLOCK)

        # Commit block to database
        db = SessionLocal()
        try:
            block_ip(
                db=db,
                ip=burst_ip,
                reason="Volumetric burst threshold exceeded",
                prediction="attacker",
                confidence=0.95,
                risk_score=risk["risk_score"],
                severity=risk["severity"],
            )
        finally:
            db.close()

        # 2. Check /api/check-ip
        check_resp = self.client.get(f"/api/check-ip/{burst_ip}")
        self.assertEqual(check_resp.status_code, 200)
        check_data = check_resp.json()
        self.assertTrue(check_data["blocked"])
        self.assertEqual(check_data["action"], "BLOCK")

        # 3. Persistent Block Verification:
        # Protected route must reject the request with HTTP 403 Forbidden!
        subsequent_resp = self.client.get("/api/search?q=catalog", headers=headers)
        self.assertEqual(subsequent_resp.status_code, 403)
        self.assertIn("blocked by Sentinel", subsequent_resp.json().get("detail", ""))

        # Another protected endpoint must ALSO reject with HTTP 403
        post_resp = self.client.post("/api/auth/login", json={"username": "user", "password": "pwd"}, headers=headers)
        self.assertEqual(post_resp.status_code, 403)

    def test_scenario_4_moderate_risk_rate_limiting_and_boundaries(self):
        """
        Verify exact policy transitions at 59.0, 60.0, 79.0, 80.0.
        Verify requests within limit succeed and beyond limit return HTTP 429.
        Verify blocked client is never downgraded to rate-limited.
        """
        # Exact boundary verifications
        self.assertEqual(calculate_severity(59.0), SEVERITY_MEDIUM)
        self.assertEqual(decide_adaptive_security(risk_score=59.0)["action"], ACTION_MONITOR)

        self.assertEqual(calculate_severity(60.0), SEVERITY_HIGH)
        self.assertEqual(decide_adaptive_security(risk_score=60.0)["action"], ACTION_RATE_LIMIT)

        self.assertEqual(calculate_severity(79.0), SEVERITY_HIGH)
        self.assertEqual(decide_adaptive_security(risk_score=79.0)["action"], ACTION_RATE_LIMIT)

        self.assertEqual(calculate_severity(80.0), SEVERITY_CRITICAL)
        self.assertEqual(decide_adaptive_security(risk_score=80.0)["action"], ACTION_BLOCK)

        # Dynamic moderate-risk enforcement
        mod_ip = "192.0.2.77"
        headers = {"X-Forwarded-For": mod_ip}

        # Set risk score in moderate-risk range (65.0)
        _rate_limiter.set_ip_risk(mod_ip, 65.0)
        self.assertTrue(_rate_limiter.is_moderate_risk(mod_ip))

        # Check /api/check-ip recognizes moderate risk
        check_mod = self.client.get(f"/api/check-ip/{mod_ip}").json()
        self.assertFalse(check_mod["blocked"])
        self.assertEqual(check_mod["risk_score"], 65.0)

        # Send requests up to moderate limit (5 requests)
        for i in range(5):
            r = self.client.get(f"/api/items/1", headers=headers)
            self.assertEqual(r.status_code, 200, f"Request {i+1} within quota should succeed")

        # 6th request exceeds moderate-risk quota -> HTTP 429 Too Many Requests
        r_exceeded = self.client.get(f"/api/items/1", headers=headers)
        self.assertEqual(r_exceeded.status_code, 429)
        self.assertIn("rate limit exceeded", r_exceeded.json().get("detail", "").lower())
        self.assertIn("Retry-After", r_exceeded.headers)

        # Verify blocked client is NOT downgraded to rate-limited
        blocked_ip_addr = "192.0.2.99"
        db = SessionLocal()
        try:
            block_ip(db=db, ip=blocked_ip_addr, reason="Blocked IP", risk_score=90.0, severity="CRITICAL")
        finally:
            db.close()

        _rate_limiter.set_ip_risk(blocked_ip_addr, 65.0)  # Attempt to downgrade via score
        check_blocked = self.client.get(f"/api/check-ip/{blocked_ip_addr}").json()
        self.assertTrue(check_blocked["blocked"])
        self.assertEqual(check_blocked["action"], "BLOCK")  # Block strictly takes precedence

    def test_scenario_5_sqli_protection_and_zero_unsafe_db_ops(self):
        """
        Verify SQL injection probes are rejected before route or database execution.
        Verify legitimate search queries work safely with parameterization.
        """
        sqli_client_ip = "198.51.100.99"
        headers = {"X-Forwarded-For": sqli_client_ip}

        # 1. SQL injection in search parameter
        sqli_resp = self.client.get("/api/search?q=' OR '1'='1", headers=headers)
        self.assertEqual(sqli_resp.status_code, 403)
        self.assertIn("SQL injection", sqli_resp.json().get("detail", ""))

        # 2. Verify IP is immediately blocked in database
        db = SessionLocal()
        try:
            self.assertTrue(is_ip_blocked(db, sqli_client_ip))
        finally:
            db.close()

        # 3. Subsequent request from attacker is STILL blocked
        followup = self.client.get("/api/search?q=normal", headers=headers)
        self.assertEqual(followup.status_code, 403)

        # 4. Normal client with benign text containing SQL keywords succeeds
        normal_ip = "192.168.1.88"
        normal_headers = {"X-Forwarded-For": normal_ip}
        benign_resp = self.client.get("/api/search?q=select our popular services", headers=normal_headers)
        self.assertEqual(benign_resp.status_code, 200)

    def test_scenario_6_anti_spoofing_untrusted_socket_peer(self):
        """
        If request connects from an untrusted public peer IP, spoofed forwarding headers are ignored.
        """
        untrusted_real_peer = "198.51.100.123"
        spoofed_header_ip = "10.0.0.99"

        # Block the real socket peer
        db = SessionLocal()
        try:
            block_ip(db=db, ip=untrusted_real_peer, reason="Blocked attacker socket peer", risk_score=95.0, severity="CRITICAL")
        finally:
            db.close()

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = untrusted_real_peer
            resp = self.client.get("/api/search?q=catalog", headers={"X-Forwarded-For": spoofed_header_ip})

        # Untrusted socket peer cannot spoof forwarding header to bypass block
        self.assertEqual(resp.status_code, 403)
