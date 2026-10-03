"""
Targeted Chakravyuh Sentinel Hardening Test Suite
Verifies:
1. RateLimiter non-mutating check_allowed() vs state-mutating is_allowed()
2. Authoritative single-slot consumption guarantee
3. /api/check-ip endpoint strictly non-mutating read operation
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from app.rate_limit_middleware import RateLimiter, _rate_limiter
from app.main import app


class TestChakravyuhHardening(unittest.TestCase):

    def test_1_rate_limiter_non_mutating_check(self):
        """Verify check_allowed() does NOT mutate sliding-window state or consume slots."""
        limiter = RateLimiter(max_requests=10, window_seconds=60, burst=2)
        test_ip = "10.0.0.99"

        # Initially 0 requests
        self.assertEqual(len(limiter.request_history[test_ip]), 0)

        # Call check_allowed multiple times
        for _ in range(5):
            allowed, info = limiter.check_allowed(test_ip)
            self.assertTrue(allowed)
            self.assertEqual(info["remaining"], 10)
            self.assertEqual(info["current"], 0)

        # Still 0 requests recorded!
        self.assertEqual(len(limiter.request_history[test_ip]), 0)

        # Calling is_allowed() consumes exactly 1 slot
        allowed, info = limiter.is_allowed(test_ip)
        self.assertTrue(allowed)
        self.assertEqual(len(limiter.request_history[test_ip]), 1)
        self.assertEqual(info["remaining"], 9)
        self.assertEqual(info["current"], 1)

        # Subsequent check_allowed still does NOT consume another slot
        allowed2, info2 = limiter.check_allowed(test_ip)
        self.assertTrue(allowed2)
        self.assertEqual(len(limiter.request_history[test_ip]), 1)
        self.assertEqual(info2["remaining"], 9)
        print("PASS: RateLimiter non-mutating check_allowed verified (single-decision guarantee).")

    def test_2_check_ip_endpoint_non_mutating(self):
        """Verify GET /api/check-ip/{ip} does NOT mutate rate limit history or consume slots."""
        client = TestClient(app)
        test_ip = "192.168.100.222"

        # Query /api/check-ip multiple times
        initial_history_len = len(_rate_limiter.request_history[test_ip])
        self.assertEqual(initial_history_len, 0)

        for _ in range(4):
            resp = client.get(f"/api/check-ip/{test_ip}")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertFalse(data["blocked"])
            self.assertFalse(data["rate_limited"])
            self.assertEqual(data["action"], "ALLOW")

        # Must still be 0 requests in rate limiter history
        after_history_len = len(_rate_limiter.request_history[test_ip])
        self.assertEqual(after_history_len, 0)
        print("PASS: /api/check-ip endpoint verified strictly non-mutating.")


if __name__ == "__main__":
    unittest.main()
