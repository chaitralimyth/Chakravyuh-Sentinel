"""
Regression and Hardening Test Suite for Chakravyuh Sentinel Backend
Validates:
1. RateLimitMiddleware downstream route execution prevention on HTTP 429
2. Rate limiting quotas, bursts, exemptions, localhost safeguard, and headers
3. Numerical validation: rejection of NaN, +Inf, -Inf across risk engine and adaptive agent
4. Exact decision boundaries (0, 28.9, 29.0, 29.1, 58.9, 59.0, 59.1, 78.9, 79.0, 79.1, 80.0, 100.0)
5. Middleware ordering and IPBlockMiddleware interaction
"""

import os
import sys
import math
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

# Ensure backend root is on sys.path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, engine, SessionLocal
from app.main import app
from app.db_models import BlockedIP, RequestLog, SessionRecord, SecurityAlert, RateLimitEvent
from app.blocking_service import block_ip, is_ip_blocked
from app.rate_limit_middleware import RateLimiter, _rate_limiter, RateLimitMiddleware
from app.config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
from app.risk_engine import (
    clamp,
    calculate_risk,
    calculate_severity,
    calculate_request_rate_score,
    calculate_auth_failure_score,
    calculate_endpoint_risk,
)
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


class TestRateLimitEnforcementHardening(unittest.TestCase):
    """Regression tests verifying that rate-limiting drops requests before handlers execute."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    def test_regression_rate_limit_prevents_downstream_handler_execution(self):
        """
        REGRESSION TEST FOR DEFECT ENF-T05B:
        When a request exceeds the configured quota, HTTP 429 must be returned,
        AND the protected downstream route handler execution counter must NOT increment.
        """
        handler_execution_count = 0

        @app.get("/api/test-protected-counter")
        def protected_route():
            nonlocal handler_execution_count
            handler_execution_count += 1
            return {"status": "success", "count": handler_execution_count}

        test_ip = "198.51.100.77"

        # Exhaust quota for test_ip on the global _rate_limiter
        for _ in range(RATE_LIMIT_REQUESTS + 50):
            _rate_limiter.is_allowed(test_ip)

        initial_count = handler_execution_count

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = test_ip
            resp = self.client.get("/api/test-protected-counter")

        # 1. Assert HTTP 429 Too Many Requests
        self.assertEqual(resp.status_code, 429, f"Expected 429, got {resp.status_code}: {resp.text}")
        self.assertIn("Rate limit exceeded", resp.json().get("detail", ""))
        self.assertIn("Retry-After", resp.headers)

        # 2. Assert handler execution count did NOT increment
        self.assertEqual(
            handler_execution_count,
            initial_count,
            "CRITICAL REGRESSION: Downstream handler executed despite HTTP 429 rejection!"
        )

    def test_allowed_request_executes_handler_and_attaches_headers(self):
        """Allowed requests must execute the handler and include X-RateLimit headers."""
        handler_runs = 0

        @app.get("/api/test-allowed-counter")
        def allowed_route():
            nonlocal handler_runs
            handler_runs += 1
            return {"ok": True}

        fresh_ip = "192.168.200.5"

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = fresh_ip
            resp = self.client.get("/api/test-allowed-counter")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(handler_runs, 1)
        self.assertIn("X-RateLimit-Limit", resp.headers)
        self.assertIn("X-RateLimit-Remaining", resp.headers)
        self.assertIn("X-RateLimit-Reset", resp.headers)
        self.assertIn("X-RateLimit-Window", resp.headers)

    def test_exempt_paths_bypass_rate_limit(self):
        """Exempt monitoring paths (/stats, /docs, /openapi.json) must remain accessible."""
        exhausted_ip = "198.51.100.90"
        for _ in range(RATE_LIMIT_REQUESTS + 30):
            _rate_limiter.is_allowed(exhausted_ip)

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = exhausted_ip
            resp_stats = self.client.get("/stats")
            resp_docs = self.client.get("/docs")

        self.assertEqual(resp_stats.status_code, 200)
        self.assertEqual(resp_docs.status_code, 200)

    def test_localhost_safeguard(self):
        """Localhost IPs (127.0.0.1, localhost) are safeguarded from rate limiting."""
        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = "127.0.0.1"
            for _ in range(5):
                resp = self.client.get("/")
                self.assertEqual(resp.status_code, 200)

    def test_middleware_ordering_ip_block_takes_precedence_over_rate_limit(self):
        """
        Verify that active IP blocking stops the request before business logic,
        and that a blocked IP cannot trigger unexpected downstream executions.
        """
        blocked_test_ip = "198.51.100.222"
        db = SessionLocal()
        try:
            block_ip(
                db=db,
                ip=blocked_test_ip,
                reason="Pre-route block test",
                prediction="attacker",
                confidence=0.95,
                risk_score=90.0,
                severity="CRITICAL",
            )
        finally:
            db.close()

        with patch("fastapi.Request.client") as mock_client:
            mock_client.host = blocked_test_ip
            resp = self.client.post("/analyze", json={"url": "http://example.com"})

        self.assertEqual(resp.status_code, 403)
        self.assertIn("blocked by Sentinel", resp.text)


class TestNumericalValidationHardening(unittest.TestCase):
    """Unit tests for hardened numerical validation across risk_engine and adaptive_agent."""

    def test_clamp_rejects_nan_and_infinities(self):
        """clamp() must raise ValueError for NaN, +Inf, -Inf."""
        with self.assertRaises(ValueError) as ctx:
            clamp(float("nan"), name="test_signal")
        self.assertIn("must be a finite real number", str(ctx.exception))

        with self.assertRaises(ValueError):
            clamp(float("inf"), name="test_signal")

        with self.assertRaises(ValueError):
            clamp(float("-inf"), name="test_signal")

    def test_clamp_handles_valid_finite_values(self):
        """clamp() preserves valid floats and clamps finite out-of-range values."""
        self.assertEqual(clamp(0.0), 0.0)
        self.assertEqual(clamp(0.5), 0.5)
        self.assertEqual(clamp(1.0), 1.0)
        self.assertEqual(clamp(-5.0), 0.0)
        self.assertEqual(clamp(10.0), 1.0)
        self.assertEqual(clamp(None), 0.0)

    def test_calculate_request_rate_score_validation(self):
        """calculate_request_rate_score() must reject NaN and Inf."""
        with self.assertRaises(ValueError):
            calculate_request_rate_score(float("nan"))

        with self.assertRaises(ValueError):
            calculate_request_rate_score(float("inf"))

        # Valid mappings
        self.assertEqual(calculate_request_rate_score(0.0), 0.0)
        self.assertEqual(calculate_request_rate_score(2.0), 0.0)
        self.assertAlmostEqual(calculate_request_rate_score(11.0), 0.5)
        self.assertEqual(calculate_request_rate_score(20.0), 1.0)
        self.assertEqual(calculate_request_rate_score(50.0), 1.0)

    def test_calculate_risk_rejects_nan_inputs(self):
        """calculate_risk() must reject NaN for any of the 5 input signals."""
        with self.assertRaises(ValueError) as ctx:
            calculate_risk(url_attack_probability=float("nan"))
        self.assertIn("url_attack_probability", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            calculate_risk(behavior_attack_probability=float("nan"))
        self.assertIn("behavior_attack_probability", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            calculate_risk(request_rate_score=float("nan"))
        self.assertIn("request_rate_score", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            calculate_risk(auth_failure_score=float("nan"))
        self.assertIn("auth_failure_score", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            calculate_risk(endpoint_risk_score=float("nan"))
        self.assertIn("endpoint_risk_score", str(ctx.exception))

    def test_calculate_risk_rejects_infinities(self):
        """calculate_risk() must reject +Inf and -Inf for signals."""
        with self.assertRaises(ValueError):
            calculate_risk(url_attack_probability=float("inf"))

        with self.assertRaises(ValueError):
            calculate_risk(behavior_attack_probability=float("-inf"))

    def test_calculate_risk_exact_boundary_scores(self):
        """Verify boundary scores 0.0 and 100.0 and component scaling."""
        min_res = calculate_risk(0.0, 0.0, 0.0, 0.0, 0.0)
        self.assertEqual(min_res["risk_score"], 0.0)
        self.assertEqual(min_res["severity"], "LOW")

        max_res = calculate_risk(1.0, 1.0, 1.0, 1.0, 1.0)
        self.assertEqual(max_res["risk_score"], 100.0)
        self.assertEqual(max_res["severity"], "CRITICAL")

    def test_adaptive_agent_exact_threshold_boundaries(self):
        """
        Verify exact policy action transitions immediately below, at, and above
        each decision threshold (29.0, 59.0, 79.0).
        """
        # --- Threshold 1: 29.0 (ALLOW -> MONITOR) ---
        dec_below_29 = decide_adaptive_security(risk_score=28.9)
        self.assertEqual(dec_below_29["action"], ACTION_ALLOW)
        self.assertEqual(dec_below_29["severity"], SEVERITY_LOW)

        dec_at_29 = decide_adaptive_security(risk_score=29.0)
        self.assertEqual(dec_at_29["action"], ACTION_ALLOW)
        self.assertEqual(dec_at_29["severity"], SEVERITY_LOW)

        dec_above_29 = decide_adaptive_security(risk_score=29.1)
        self.assertEqual(dec_above_29["action"], ACTION_MONITOR)
        self.assertEqual(dec_above_29["severity"], SEVERITY_MEDIUM)

        dec_fractional_299 = decide_adaptive_security(risk_score=29.9)
        self.assertEqual(dec_fractional_299["action"], ACTION_MONITOR)
        self.assertEqual(dec_fractional_299["severity"], SEVERITY_MEDIUM)

        dec_at_30 = decide_adaptive_security(risk_score=30.0)
        self.assertEqual(dec_at_30["action"], ACTION_MONITOR)
        self.assertEqual(dec_at_30["severity"], SEVERITY_MEDIUM)

        # --- Threshold 2: 59.0 (MONITOR -> RATE_LIMIT) ---
        dec_below_59 = decide_adaptive_security(risk_score=58.9)
        self.assertEqual(dec_below_59["action"], ACTION_MONITOR)
        self.assertEqual(dec_below_59["severity"], SEVERITY_MEDIUM)

        dec_at_59 = decide_adaptive_security(risk_score=59.0)
        self.assertEqual(dec_at_59["action"], ACTION_MONITOR)
        self.assertEqual(dec_at_59["severity"], SEVERITY_MEDIUM)

        dec_above_59 = decide_adaptive_security(risk_score=59.1)
        self.assertEqual(dec_above_59["action"], ACTION_RATE_LIMIT)
        self.assertEqual(dec_above_59["severity"], SEVERITY_HIGH)

        dec_at_60 = decide_adaptive_security(risk_score=60.0)
        self.assertEqual(dec_at_60["action"], ACTION_RATE_LIMIT)
        self.assertEqual(dec_at_60["severity"], SEVERITY_HIGH)

        # --- Threshold 3: 79.0 (RATE_LIMIT -> BLOCK) ---
        dec_below_79 = decide_adaptive_security(risk_score=78.9)
        self.assertEqual(dec_below_79["action"], ACTION_RATE_LIMIT)
        self.assertEqual(dec_below_79["severity"], SEVERITY_HIGH)

        dec_at_79 = decide_adaptive_security(risk_score=79.0)
        self.assertEqual(dec_at_79["action"], ACTION_RATE_LIMIT)
        self.assertEqual(dec_at_79["severity"], SEVERITY_HIGH)

        dec_above_79 = decide_adaptive_security(risk_score=79.1)
        self.assertEqual(dec_above_79["action"], ACTION_BLOCK)
        self.assertEqual(dec_above_79["severity"], SEVERITY_CRITICAL)

        dec_at_80 = decide_adaptive_security(risk_score=80.0)
        self.assertEqual(dec_at_80["action"], ACTION_BLOCK)
        self.assertEqual(dec_at_80["severity"], SEVERITY_CRITICAL)

        # --- Boundary extremes ---
        dec_zero = decide_adaptive_security(risk_score=0.0)
        self.assertEqual(dec_zero["action"], ACTION_ALLOW)

        dec_hundred = decide_adaptive_security(risk_score=100.0)
        self.assertEqual(dec_hundred["action"], ACTION_BLOCK)

    def test_severity_boundary_consistency_between_risk_engine_and_adaptive_agent(self):
        """
        Regression test for severity-boundary consistency between risk_engine and adaptive_agent:
        Verifies exact action and severity alignment for boundary values, specifically:
        29.0, 29.01, 29.5, and 30.0, as well as 59.0, 59.01, 59.5, 60.0, 79.0, 79.01, 79.5, 80.0.
        """
        test_points = [
            # (risk_score, expected_action, expected_severity)
            (0.0, ACTION_ALLOW, SEVERITY_LOW),
            (28.99, ACTION_ALLOW, SEVERITY_LOW),
            (29.0, ACTION_ALLOW, SEVERITY_LOW),
            (29.01, ACTION_MONITOR, SEVERITY_MEDIUM),
            (29.5, ACTION_MONITOR, SEVERITY_MEDIUM),
            (30.0, ACTION_MONITOR, SEVERITY_MEDIUM),
            (58.99, ACTION_MONITOR, SEVERITY_MEDIUM),
            (59.0, ACTION_MONITOR, SEVERITY_MEDIUM),
            (59.01, ACTION_RATE_LIMIT, SEVERITY_HIGH),
            (59.5, ACTION_RATE_LIMIT, SEVERITY_HIGH),
            (60.0, ACTION_RATE_LIMIT, SEVERITY_HIGH),
            (78.99, ACTION_RATE_LIMIT, SEVERITY_HIGH),
            (79.0, ACTION_RATE_LIMIT, SEVERITY_HIGH),
            (79.01, ACTION_BLOCK, SEVERITY_CRITICAL),
            (79.5, ACTION_BLOCK, SEVERITY_CRITICAL),
            (80.0, ACTION_BLOCK, SEVERITY_CRITICAL),
            (100.0, ACTION_BLOCK, SEVERITY_CRITICAL),
        ]

        for score, exp_action, exp_severity in test_points:
            # 1. Test risk_engine severity calculation
            eng_sev = calculate_severity(score)
            self.assertEqual(
                eng_sev,
                exp_severity,
                f"risk_engine severity mismatch for score={score}: expected {exp_severity}, got {eng_sev}"
            )

            # 2. Test adaptive_agent decision (both action and derived severity)
            agent_dec = decide_adaptive_security(risk_score=score)
            self.assertEqual(
                agent_dec["action"],
                exp_action,
                f"adaptive_agent action mismatch for score={score}: expected {exp_action}, got {agent_dec['action']}"
            )
            self.assertEqual(
                agent_dec["severity"],
                exp_severity,
                f"adaptive_agent severity mismatch for score={score}: expected {exp_severity}, got {agent_dec['severity']}"
            )

            # 3. Test end-to-end alignment when risk_engine severity is explicitly passed to adaptive_agent
            e2e_dec = decide_adaptive_security(risk_score=score, severity=eng_sev)
            self.assertEqual(
                e2e_dec["action"],
                exp_action,
                f"e2e action mismatch for score={score} with eng_sev={eng_sev}"
            )
            self.assertEqual(
                e2e_dec["severity"],
                exp_severity,
                f"e2e severity mismatch for score={score} with eng_sev={eng_sev}: expected {exp_severity}, got {e2e_dec['severity']}"
            )

    def test_adaptive_agent_rejects_out_of_range_and_non_finite(self):
        """adaptive_agent.decide_adaptive_security() must reject out-of-bounds and NaN/inf."""
        with self.assertRaises(ValueError):
            decide_adaptive_security(risk_score=-0.1)

        with self.assertRaises(ValueError):
            decide_adaptive_security(risk_score=100.1)

        with self.assertRaises(ValueError):
            decide_adaptive_security(risk_score=float("nan"))

        with self.assertRaises(ValueError):
            decide_adaptive_security(risk_score=float("inf"))

        with self.assertRaises(TypeError):
            decide_adaptive_security(risk_score="85")

        with self.assertRaises(TypeError):
            decide_adaptive_security(risk_score=True)


if __name__ == "__main__":
    unittest.main()
