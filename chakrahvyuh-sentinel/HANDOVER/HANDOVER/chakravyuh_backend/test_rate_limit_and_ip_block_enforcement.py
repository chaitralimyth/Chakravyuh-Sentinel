"""
Automated Verification Test Suite: Rate Limiting and IP Blocking Enforcement
Validates:
1. Normal requests below threshold succeed (HTTP 200)
2. Requests within configured allowance succeed
3. Requests exceeding configured allowance receive HTTP 429 Too Many Requests
4. Rate-limit counter persists throughout the configured time window
5. Independent client identities are handled separately
6. Configured blocking action is persisted in database
7. Subsequent request from blocked client receives HTTP 403 Forbidden
8. Unblocked client can access the endpoint (HTTP 200)
9. Dashboard request monitoring and recovery endpoints (/requests, /stats, /alerts, /api/unblock-ip) remain accessible when client is blocked
10. Restart behavior matches database persistence guarantees
"""

import os
import sys
import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from fastapi.testclient import TestClient
from app.database import Base, engine, SessionLocal
from app.main import app
from app.db_models import BlockedIP, RequestLog, RateLimitEvent
from app.blocking_service import block_ip, is_ip_blocked
from app.rate_limit_middleware import RateLimiter, _rate_limiter
from app.config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS


class TestRateLimitingAndIPBlockingEnforcement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    def test_1_normal_requests_within_allowance_succeed(self):
        """Requests within configured threshold (e.g. up to 5) succeed with HTTP 200 and rate limit headers."""
        test_ip = "192.0.2.11"
        _rate_limiter.reset_ip(test_ip)

        for i in range(RATE_LIMIT_REQUESTS):
            with patch("fastapi.Request.client") as mock_client:
                mock_client.host = test_ip
                # Test protected route: /predict-url
                post_resp = self.client.post("/predict-url", json={"url": f"http://example.com/item{i}"})
                self.assertEqual(post_resp.status_code, 200, f"Request {i+1} failed: {post_resp.text}")
                self.assertIn("X-RateLimit-Limit", post_resp.headers)
                self.assertIn("X-RateLimit-Remaining", post_resp.headers)
                self.assertEqual(post_resp.headers["X-RateLimit-Limit"], str(RATE_LIMIT_REQUESTS))

    def test_2_request_exceeding_allowance_receives_429(self):
        """A request exceeding the allowance receives HTTP 429 Too Many Requests with headers."""
        test_ip = "192.0.2.22"
        _rate_limiter.reset_ip(test_ip)

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = test_ip
            # Send requests up to quota
            for i in range(RATE_LIMIT_REQUESTS):
                r = self.client.post("/predict-url", json={"url": f"http://example.com/page{i}"})
                self.assertEqual(r.status_code, 200)

            # (Quota + 1)th request MUST return HTTP 429
            exceeded_resp = self.client.post("/predict-url", json={"url": "http://example.com/exceeded"})
            self.assertEqual(exceeded_resp.status_code, 429)
            body = exceeded_resp.json()
            self.assertIn("detail", body)
            self.assertIn("rate_limit", body)
            self.assertEqual(body["rate_limit"]["remaining"], 0)
            self.assertIn("Retry-After", exceeded_resp.headers)
            self.assertEqual(exceeded_resp.headers["X-RateLimit-Remaining"], "0")

    def test_3_rate_limit_counter_persists_in_window(self):
        """Rate limit counter persists throughout the window and tracks request count accurately."""
        test_ip = "192.0.2.33"
        _rate_limiter.reset_ip(test_ip)

        stats_initial = _rate_limiter.get_stats(test_ip)
        self.assertEqual(stats_initial["current"], 0)

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = test_ip
            for i in range(3):
                self.client.post("/predict-url", json={"url": f"http://example.com/p{i}"})

        stats_after = _rate_limiter.get_stats(test_ip)
        self.assertEqual(stats_after["current"], 3)
        self.assertEqual(stats_after["remaining"], max(0, RATE_LIMIT_REQUESTS - 3))

    def test_4_independent_client_identities_handled_separately(self):
        """Rate limiting one IP does not affect an independent client IP."""
        client_a = "192.0.2.44"
        client_b = "192.0.2.55"
        _rate_limiter.reset_ip(client_a)
        _rate_limiter.reset_ip(client_b)

        # Exhaust Client A
        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = client_a
            for _ in range(RATE_LIMIT_REQUESTS + 1):
                self.client.post("/predict-url", json={"url": "http://example.com/a"})

            resp_a = self.client.post("/predict-url", json={"url": "http://example.com/a-blocked"})
            self.assertEqual(resp_a.status_code, 429)

        # Client B must succeed (HTTP 200)
        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = client_b
            resp_b = self.client.post("/predict-url", json={"url": "http://example.com/b"})
            self.assertEqual(resp_b.status_code, 200)

    def test_5_blocking_persisted_and_enforced_with_403(self):
        """A configured BLOCK action creates a DB record and rejects subsequent protected requests with 403."""
        blocked_ip_addr = "198.51.100.88"
        db = SessionLocal()
        try:
            # Create authoritative block
            block = block_ip(
                db=db,
                ip=blocked_ip_addr,
                reason="Empirical evaluation security block test",
                prediction="attacker",
                confidence=0.99,
                risk_score=95.0,
                severity="CRITICAL",
            )
            self.assertIsNotNone(block.id)
            self.assertTrue(block.is_active)
            self.assertEqual(block.ip, blocked_ip_addr)
        finally:
            db.close()

        # Verify is_ip_blocked consults the database
        db_check = SessionLocal()
        try:
            self.assertTrue(is_ip_blocked(db_check, blocked_ip_addr))
        finally:
            db_check.close()

        # Subsequent request from blocked client to protected endpoint receives HTTP 403
        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = blocked_ip_addr
            resp = self.client.post("/predict-url", json={"url": "http://example.com/test"})
            self.assertEqual(resp.status_code, 403)
            self.assertIn("blocked by Sentinel", resp.json().get("detail", ""))

    def test_6_unblock_restores_client_access(self):
        """An unblocked client regains access to protected routes."""
        test_ip = "198.51.100.99"
        db = SessionLocal()
        try:
            block_ip(db=db, ip=test_ip, reason="Temporary test block", risk_score=90.0)
        finally:
            db.close()

        # Call unblock endpoint
        unblock_resp = self.client.post("/api/unblock-ip", json={"ip": test_ip})
        self.assertEqual(unblock_resp.status_code, 200)
        self.assertTrue(unblock_resp.json()["success"])

        # Client now receives HTTP 200
        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = test_ip
            resp = self.client.post("/predict-url", json={"url": "http://example.com/unblocked"})
            self.assertEqual(resp.status_code, 200)

    def test_7_dashboard_monitoring_and_recovery_preserved_when_ip_blocked(self):
        """Dashboard monitoring (/requests, /stats, /alerts, /blocked-ips, /api/unblock-ip) remains accessible even when client IP is blocked."""
        blocked_ip_addr = "198.51.100.111"
        db = SessionLocal()
        try:
            block_ip(db=db, ip=blocked_ip_addr, reason="Block test for dashboard monitoring", risk_score=95.0)
        finally:
            db.close()

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = blocked_ip_addr

            # 1. /requests endpoint MUST return 200 (not 403)
            resp_requests = self.client.get("/requests")
            self.assertEqual(resp_requests.status_code, 200)

            # 2. /stats endpoint MUST return 200
            resp_stats = self.client.get("/stats")
            self.assertEqual(resp_stats.status_code, 200)

            # 3. /alerts endpoint MUST return 200
            resp_alerts = self.client.get("/alerts")
            self.assertEqual(resp_alerts.status_code, 200)

            # 4. /blocked-ips endpoint MUST return 200
            resp_blocked = self.client.get("/blocked-ips")
            self.assertEqual(resp_blocked.status_code, 200)

            # 5. /api/unblock-ip MUST return 200
            resp_unblock = self.client.post("/api/unblock-ip", json={"ip": blocked_ip_addr})
            self.assertEqual(resp_unblock.status_code, 200)

            # 6. Protected business route MUST still be blocked if re-blocked
            block_ip(db=SessionLocal(), ip=blocked_ip_addr, reason="Re-block")
            resp_protected = self.client.post("/predict-url", json={"url": "http://example.com"})
            self.assertEqual(resp_protected.status_code, 403)

    def test_8_restart_persistence_from_database(self):
        """A new RateLimiter instance (simulating restart) loads recent DB request logs and enforces limits."""
        test_ip = "192.0.2.77"
        now = datetime.now(timezone.utc)

        # Insert 5 recent RequestLog entries into DB for this IP
        db = SessionLocal()
        try:
            for i in range(5):
                log = RequestLog(
                    ip=test_ip,
                    method="GET",
                    endpoint="/api/services",
                    status_code=200,
                    timestamp=now - timedelta(seconds=i * 2),
                    source_site="x-beauty",
                )
                db.add(log)
            db.commit()
        finally:
            db.close()

        # Create a new RateLimiter with sync_db=True (simulating backend restart)
        restarted_limiter = RateLimiter(max_requests=5, window_seconds=60, burst=0, sync_db=True)

        # Check: 6th request should be rejected because 5 are already in DB window
        allowed, info = restarted_limiter.is_allowed(test_ip)
        self.assertFalse(allowed, "Restarted rate limiter failed to synchronize existing request logs from DB!")
        self.assertEqual(info["remaining"], 0)
        self.assertEqual(info["current"], 5)


if __name__ == "__main__":
    unittest.main()
