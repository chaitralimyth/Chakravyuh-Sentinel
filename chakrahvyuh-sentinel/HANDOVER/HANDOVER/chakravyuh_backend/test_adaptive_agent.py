"""
Comprehensive Unit Tests for Adaptive Security Agent.

Tests:
1. Decision policy: ALLOW, MONITOR, RATE_LIMIT, BLOCK
2. Exact boundaries: 0, 29, 30, 59, 60, 79, 80, 100
3. Floating point boundaries: 29.9, 59.9, 79.9
4. Missing optional context resilience (no crash)
5. Out-of-range and invalid input validation
6. Structured reasoning & explainability
7. Deterministic reproducibility
8. RATE_LIMIT non-fake enforcement separation
9. BLOCK integration with blocking_service (with enforce_block=True)
10. Policy introspection
"""

import math
import os
import sys
import unittest
from datetime import datetime, timezone

# Ensure backend directory is in python path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Set test database URL before importing app modules
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.adaptive_agent import (
    AdaptiveSecurityAgent,
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


class TestAdaptiveSecurityAgent(unittest.TestCase):
    def setUp(self):
        self.agent = AdaptiveSecurityAgent()

    # ---------------------------------------------------------
    # 1. 4-Tier Policy Tests
    # ---------------------------------------------------------
    def test_low_risk_maps_to_allow(self):
        decision = self.agent.decide(risk_score=15.0)
        self.assertEqual(decision["action"], ACTION_ALLOW)
        self.assertEqual(decision["severity"], SEVERITY_LOW)
        self.assertTrue(decision["enforcement"]["enforced"])

    def test_medium_risk_maps_to_monitor(self):
        decision = self.agent.decide(risk_score=45.0)
        self.assertEqual(decision["action"], ACTION_MONITOR)
        self.assertEqual(decision["severity"], SEVERITY_MEDIUM)
        self.assertTrue(decision["enforcement"]["enforced"])

    def test_high_risk_maps_to_rate_limit(self):
        decision = self.agent.decide(risk_score=70.0)
        self.assertEqual(decision["action"], ACTION_RATE_LIMIT)
        self.assertEqual(decision["severity"], SEVERITY_HIGH)
        # Verify rate-limit enforcement is NOT faked
        self.assertFalse(decision["enforcement"]["enforced"])
        self.assertEqual(decision["enforcement"]["mechanism"], "none")

    def test_critical_risk_maps_to_block(self):
        decision = self.agent.decide(risk_score=91.0)
        self.assertEqual(decision["action"], ACTION_BLOCK)
        self.assertEqual(decision["severity"], SEVERITY_CRITICAL)
        # Default enforce_block=False keeps live pipeline safe
        self.assertFalse(decision["enforcement"]["enforced"])

    # ---------------------------------------------------------
    # 2. Exact Boundary Tests
    # ---------------------------------------------------------
    def test_boundary_0(self):
        d = self.agent.decide(0)
        self.assertEqual(d["action"], ACTION_ALLOW)
        self.assertEqual(d["severity"], SEVERITY_LOW)

    def test_boundary_29(self):
        d = self.agent.decide(29)
        self.assertEqual(d["action"], ACTION_ALLOW)
        self.assertEqual(d["severity"], SEVERITY_LOW)

    def test_boundary_30(self):
        d = self.agent.decide(30)
        self.assertEqual(d["action"], ACTION_MONITOR)
        self.assertEqual(d["severity"], SEVERITY_MEDIUM)

    def test_boundary_59(self):
        d = self.agent.decide(59)
        self.assertEqual(d["action"], ACTION_MONITOR)
        self.assertEqual(d["severity"], SEVERITY_MEDIUM)

    def test_boundary_60(self):
        d = self.agent.decide(60)
        self.assertEqual(d["action"], ACTION_RATE_LIMIT)
        self.assertEqual(d["severity"], SEVERITY_HIGH)

    def test_boundary_79(self):
        d = self.agent.decide(79)
        self.assertEqual(d["action"], ACTION_RATE_LIMIT)
        self.assertEqual(d["severity"], SEVERITY_HIGH)

    def test_boundary_80(self):
        d = self.agent.decide(80)
        self.assertEqual(d["action"], ACTION_BLOCK)
        self.assertEqual(d["severity"], SEVERITY_CRITICAL)

    def test_boundary_100(self):
        d = self.agent.decide(100)
        self.assertEqual(d["action"], ACTION_BLOCK)
        self.assertEqual(d["severity"], SEVERITY_CRITICAL)

    def test_floating_boundaries(self):
        # 29.9 -> MONITOR (greater than allow_max 29)
        self.assertEqual(self.agent.decide(29.9)["action"], ACTION_MONITOR)
        # 59.9 -> RATE_LIMIT (greater than monitor_max 59)
        self.assertEqual(self.agent.decide(59.9)["action"], ACTION_RATE_LIMIT)
        # 79.9 -> BLOCK (greater than rate_limit_max 79)
        self.assertEqual(self.agent.decide(79.9)["action"], ACTION_BLOCK)

    # ---------------------------------------------------------
    # 3. Resilience to Missing Optional Context
    # ---------------------------------------------------------
    def test_missing_all_optional_context_does_not_crash(self):
        d = self.agent.decide(risk_score=50.0)
        self.assertEqual(d["action"], ACTION_MONITOR)
        self.assertIsNone(d["confidence"])
        self.assertEqual(d["severity"], SEVERITY_MEDIUM)
        self.assertIsNone(d["session_id"])
        self.assertIsNone(d["source_ip"])
        self.assertIsInstance(d["timestamp"], str)
        self.assertIsInstance(d["reasons"], list)
        self.assertGreater(len(d["reasons"]), 0)
        self.assertEqual(d["contributing_factors"], {"risk_score": 50.0})

    def test_empty_context_dict_handled_gracefully(self):
        d = self.agent.decide(risk_score=10.0, context={})
        self.assertEqual(d["action"], ACTION_ALLOW)
        self.assertEqual(d["contributing_factors"], {"risk_score": 10.0})

    # ---------------------------------------------------------
    # 4. Out-of-Range and Invalid Input Handling
    # ---------------------------------------------------------
    def test_negative_risk_score_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.agent.decide(risk_score=-0.1)

    def test_excessive_risk_score_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.agent.decide(risk_score=100.1)

    def test_none_risk_score_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.agent.decide(risk_score=None)

    def test_string_risk_score_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.agent.decide(risk_score="ninety")

    def test_boolean_risk_score_rejected(self):
        with self.assertRaises(TypeError):
            self.agent.decide(risk_score=True)

    def test_invalid_confidence_raises_error(self):
        with self.assertRaises(ValueError):
            self.agent.decide(risk_score=50, confidence=1.5)
        with self.assertRaises(ValueError):
            self.agent.decide(risk_score=50, confidence=-0.1)
        with self.assertRaises(TypeError):
            self.agent.decide(risk_score=50, confidence="high")

    # ---------------------------------------------------------
    # 5. Deterministic Execution
    # ---------------------------------------------------------
    def test_deterministic_repeated_calls(self):
        fixed_time = "2026-09-27T12:00:00+00:00"
        context = {
            "behavior_prediction": "attacker",
            "auth_failure_ratio": 0.4,
            "admin_endpoint_access": 3,
        }
        res1 = self.agent.decide(
            risk_score=85,
            confidence=0.92,
            context=context,
            session_id="sess_abc",
            source_ip="192.168.1.1",
            timestamp=fixed_time,
        )
        for _ in range(50):
            res2 = self.agent.decide(
                risk_score=85,
                confidence=0.92,
                context=context,
                session_id="sess_abc",
                source_ip="192.168.1.1",
                timestamp=fixed_time,
            )
            self.assertEqual(res1, res2)

    # ---------------------------------------------------------
    # 6. Structured Explainability & Reasons
    # ---------------------------------------------------------
    def test_block_reasons_avoid_unsupported_confirmed_attack_claims(self):
        # Without explicit is_confirmed_attack flag, reason must state block threshold reached
        d = self.agent.decide(risk_score=88)
        self.assertTrue(any("BLOCK threshold" in r for r in d["reasons"]))
        self.assertFalse(any("confirmed attack" in r.lower() for r in d["reasons"]))

    def test_confirmed_attack_flag_reflected_when_provided(self):
        d = self.agent.decide(risk_score=95, context={"is_confirmed_attack": True})
        self.assertTrue(any("Confirmed attack pattern" in r for r in d["reasons"]))

    def test_behavior_classification_in_reasons(self):
        d = self.agent.decide(
            risk_score=82,
            confidence=0.89,
            context={"behavior_prediction": "attacker"},
        )
        self.assertTrue(any("Behavior ML classified session as attacker" in r for r in d["reasons"]))
        self.assertTrue(any("88.9%" in r or "89.0%" in r for r in d["reasons"]))

    def test_auth_failure_in_reasons(self):
        d = self.agent.decide(risk_score=75, context={"auth_failure_ratio": 0.35})
        self.assertTrue(any("Authentication failure ratio elevated" in r for r in d["reasons"]))

    def test_admin_endpoint_access_in_reasons(self):
        d = self.agent.decide(risk_score=72, context={"admin_endpoint_access": 4})
        self.assertTrue(any("Sensitive/admin endpoint probe detected" in r for r in d["reasons"]))

    def test_suspicious_query_keywords_in_reasons(self):
        d = self.agent.decide(risk_score=65, context={"suspicious_query_keywords": 2})
        self.assertTrue(any("Suspicious query keyword pattern detected" in r for r in d["reasons"]))

    def test_request_burst_in_reasons(self):
        d = self.agent.decide(risk_score=68, context={"max_requests_per_second": 12})
        self.assertTrue(any("High request burst frequency detected" in r for r in d["reasons"]))

    def test_url_threat_in_reasons(self):
        d = self.agent.decide(risk_score=85, context={"url_risk": "phishing_tld"})
        self.assertTrue(any("URL threat indicator flagged: phishing_tld" in r for r in d["reasons"]))

    # ---------------------------------------------------------
    # 7. RATE_LIMIT Honest Enforcement Verification
    # ---------------------------------------------------------
    def test_rate_limit_honesty(self):
        d = self.agent.decide(risk_score=68)
        self.assertEqual(d["action"], ACTION_RATE_LIMIT)
        enf = d["enforcement"]
        self.assertFalse(enf["enforced"])
        self.assertEqual(enf["mechanism"], "none")
        self.assertIn("Gateway rate limiter not configured", enf["detail"])

    # ---------------------------------------------------------
    # 8. BLOCK Integration with blocking_service
    # ---------------------------------------------------------
    def test_block_service_integration_when_enforce_block_true(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.database import Base
        from app.blocking_service import is_ip_blocked

        # Isolated in-memory SQLite engine
        test_engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=test_engine)
        TestSession = sessionmaker(bind=test_engine)
        db = TestSession()

        try:
            test_ip = "10.0.0.99"
            self.assertFalse(is_ip_blocked(db, test_ip))

            decision = self.agent.decide(
                risk_score=92,
                confidence=0.95,
                source_ip=test_ip,
                session_id="sess_test_block",
                context={"behavior_prediction": "attacker"},
                db=db,
                enforce_block=True,
            )

            self.assertEqual(decision["action"], ACTION_BLOCK)
            self.assertTrue(decision["enforcement"]["enforced"])
            self.assertEqual(decision["enforcement"]["mechanism"], "blocking_service.block_ip")
            self.assertIsNotNone(decision["enforcement"]["blocked_until"])

            # Verify IP is now blocked in the database
            self.assertTrue(is_ip_blocked(db, test_ip))
        finally:
            db.close()

    # ---------------------------------------------------------
    # 9. Policy Introspection
    # ---------------------------------------------------------
    def test_policy_summary(self):
        summary = self.agent.get_policy_summary()
        self.assertIn("ALLOW", summary)
        self.assertIn("MONITOR", summary)
        self.assertIn("RATE_LIMIT", summary)
        self.assertIn("BLOCK", summary)
        self.assertEqual(summary["ALLOW"]["max"], 29)
        self.assertEqual(summary["MONITOR"]["min"], 30)
        self.assertEqual(summary["RATE_LIMIT"]["min"], 60)
        self.assertEqual(summary["BLOCK"]["min"], 80)

    # ---------------------------------------------------------
    # 10. Module-level Convenience Function
    # ---------------------------------------------------------
    def test_decide_adaptive_security_function(self):
        d = decide_adaptive_security(risk_score=20)
        self.assertEqual(d["action"], ACTION_ALLOW)
        d = decide_adaptive_security(risk_score=85)
        self.assertEqual(d["action"], ACTION_BLOCK)


if __name__ == "__main__":
    unittest.main()
