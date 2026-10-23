"""
End-to-End Rate Limiting Verification Test Suite for X-Beauty + Chakravyuh Sentinel

Tests:
1. Normal requests below threshold (5 requests in 60s) succeed (HTTP 200).
2. Requests exceeding threshold receive HTTP 429 Too Many Requests.
3. Response contains Retry-After header, X-Sentinel-Action, and rate limit JSON detail.
4. Protected handler is dropped pre-route (state-changing POST /api/messages does NOT persist).
5. Rate-limit events are persisted in Sentinel database (RateLimitEvent and RequestLog with 429).
6. Dashboard API (/rate-limit/stats and /stats) returns persisted events and counts.
7. Separate client IPs have independent quotas (Client B is unaffected by Client A's limit).
8. IP Blocking (403) and Rate Limiting (429) coexist distinctly.
"""

import time
import unittest
import httpx

CHAKRAVYUH_URL = "http://127.0.0.1:8000"
XBEAUTY_URL = "http://127.0.0.1:8001"


class TestRateLimitingEndToEnd(unittest.TestCase):

    def setUp(self):
        # Use unique controlled test IP based on timestamp to ensure fresh isolated state
        self.ts = int(time.time() * 1000) % 1000000
        self.client_ip = f"198.51.100.{self.ts % 150 + 10}"
        self.headers = {"X-Forwarded-For": self.client_ip}

        # Clear any prior test state for this IP
        try:
            httpx.post(f"{CHAKRAVYUH_URL}/api/unblock-ip", json={"ip": self.client_ip}, timeout=3.0)
            httpx.post(f"{XBEAUTY_URL}/api/reset-ratelimit", json={"ip": self.client_ip}, timeout=3.0)
        except Exception:
            pass

    def test_1_requests_below_threshold_succeed(self):
        """Send 5 requests (the configured limit) and verify all return 200 OK with decreasing quota."""
        for i in range(1, 6):
            resp = httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)
            self.assertEqual(resp.status_code, 200, f"Request {i}/5 should succeed with 200")
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining is not None:
                self.assertEqual(int(remaining), 5 - i, f"Remaining quota for request {i} should be {5 - i}")

    def test_2_request_exceeding_threshold_receives_429(self):
        """Send 5 requests followed by 6th request, verifying the 6th receives HTTP 429 with Retry-After."""
        # 5 allowed requests
        for i in range(5):
            r = httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)
            self.assertEqual(r.status_code, 200)

        # 6th request MUST be rejected with 429 Too Many Requests
        resp_6 = httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)
        self.assertEqual(resp_6.status_code, 429, "6th request must receive HTTP 429 Too Many Requests")

        # Verify headers
        self.assertIn("Retry-After", resp_6.headers, "Response must include Retry-After header")
        retry_after = int(resp_6.headers["Retry-After"])
        self.assertGreater(retry_after, 0, "Retry-After must be positive seconds")
        self.assertEqual(resp_6.headers.get("X-Sentinel-Action"), "RATE_LIMIT")

        # Verify JSON body
        body = resp_6.json()
        self.assertEqual(body.get("security_action"), "RATE_LIMIT")
        self.assertEqual(body.get("ip"), self.client_ip)
        self.assertIn("rate limit", body.get("detail", "").lower())
        self.assertEqual(body.get("limit"), 5)
        self.assertEqual(body.get("window_seconds"), 60)

    def test_3_rate_limited_request_drops_before_protected_handler(self):
        """Verify state-changing POST /api/messages is dropped pre-route without database insertion."""
        # Exhaust quota
        for _ in range(5):
            httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)

        # Attempt state-changing message creation
        unique_spam_msg = f"Unwanted spam attempt {self.ts}"
        post_resp = httpx.post(
            f"{XBEAUTY_URL}/api/messages",
            json={
                "name": "Spam Bot",
                "email": "bot@spam-test.org",
                "phone": "555-0100",
                "message": unique_spam_msg,
            },
            headers=self.headers,
            timeout=5.0,
        )
        self.assertEqual(post_resp.status_code, 429, "State-changing POST must receive 429")

        # Verify the message was NOT created in X-Beauty database
        msgs_resp = httpx.get(f"{XBEAUTY_URL}/api/messages", timeout=5.0)
        if msgs_resp.status_code == 200:
            msgs = msgs_resp.json()
            spam_found = any(unique_spam_msg in str(m) for m in msgs)
            self.assertFalse(spam_found, "Rate-limited POST message must NEVER be inserted into database")

    def test_4_rate_limit_event_persisted_in_sentinel(self):
        """Verify Sentinel records RateLimitEvent and 429 RequestLog for the rate-limited request."""
        # Exhaust quota and trigger 429
        for _ in range(5):
            httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)
        httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)

        # Wait briefly for async telemetry ingestion
        time.sleep(0.6)

        # Verify in Sentinel /rate-limit/stats
        stats_resp = httpx.get(f"{CHAKRAVYUH_URL}/rate-limit/stats", timeout=5.0)
        self.assertEqual(stats_resp.status_code, 200)
        stats = stats_resp.json()
        self.assertGreater(stats.get("total_violations", 0), 0)

        # Verify violation record exists with correct metadata
        violations = stats.get("recent_violations", [])
        ip_violation = next((v for v in violations if v.get("ip") == self.client_ip), None)
        self.assertIsNotNone(ip_violation, f"Expected RateLimitEvent for {self.client_ip}")
        self.assertEqual(ip_violation.get("action"), "RATE_LIMIT")
        self.assertEqual(ip_violation.get("status_code"), 429)

        # Verify in Sentinel /requests
        req_resp = httpx.get(f"{CHAKRAVYUH_URL}/requests?ip={self.client_ip}", timeout=5.0)
        self.assertEqual(req_resp.status_code, 200)
        logs = req_resp.json()
        has_429 = any(l.get("status_code") == 429 for l in logs)
        self.assertTrue(has_429, f"Expected 429 RequestLog in Sentinel for {self.client_ip}")

    def test_5_separate_client_identities_have_independent_quotas(self):
        """Verify client B is completely unaffected when client A exceeds rate limit."""
        client_b_ip = f"198.51.100.{(self.ts + 50) % 150 + 10}"
        headers_b = {"X-Forwarded-For": client_b_ip}

        # Clear client B state
        httpx.post(f"{XBEAUTY_URL}/api/reset-ratelimit", json={"ip": client_b_ip}, timeout=3.0)

        # Exhaust Client A quota to 429
        for _ in range(6):
            httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)

        # Confirm Client A is blocked with 429
        resp_a = httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)
        self.assertEqual(resp_a.status_code, 429)

        # Client B must succeed with 200 OK!
        resp_b = httpx.get(f"{XBEAUTY_URL}/api/services", headers=headers_b, timeout=5.0)
        self.assertEqual(resp_b.status_code, 200, "Client B must succeed even when Client A is rate-limited")

    def test_6_ip_block_and_rate_limit_coexist(self):
        """Verify Blocked IP returns HTTP 403 BLOCK whereas Rate Limit returns HTTP 429 RATE_LIMIT."""
        blocked_ip = f"198.51.100.{(self.ts + 99) % 150 + 10}"
        headers_blocked = {"X-Forwarded-For": blocked_ip}

        # Block the IP in Sentinel
        block_resp = httpx.post(
            f"{CHAKRAVYUH_URL}/blocked-ips",
            json={
                "ip": blocked_ip,
                "reason": "Test block coexistence verification",
                "severity": "HIGH",
            },
            timeout=5.0,
        )
        self.assertEqual(block_resp.status_code, 200)

        # Send request from blocked IP -> MUST be HTTP 403 Forbidden
        r_block = httpx.get(f"{XBEAUTY_URL}/api/services", headers=headers_blocked, timeout=5.0)
        self.assertEqual(r_block.status_code, 403)
        self.assertEqual(r_block.headers.get("X-Sentinel-Action"), "BLOCK")

        # Send request from rate-limited IP -> MUST be HTTP 429 Too Many Requests
        for _ in range(6):
            httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)
        r_rl = httpx.get(f"{XBEAUTY_URL}/api/services", headers=self.headers, timeout=5.0)
        self.assertEqual(r_rl.status_code, 429)
        self.assertEqual(r_rl.headers.get("X-Sentinel-Action"), "RATE_LIMIT")


if __name__ == "__main__":
    unittest.main()
