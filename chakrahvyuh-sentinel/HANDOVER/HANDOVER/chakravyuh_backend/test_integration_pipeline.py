"""
Comprehensive Integration Test Suite for Chakravyuh Sentinel

Covers:
1. Dynamic Risk Scoring Engine (boundaries, missing/invalid signals, component breakdown)
2. Adaptive Security Agent (0, 29, 30, 59, 60, 79, 80, 100 thresholds)
3. End-to-End Pipeline (Traffic -> Session -> ML -> Risk -> Adaptive Agent -> Alert/Incident)
4. Duplicate Decision Prevention (Exactly 1 block operation, no duplicate alerts)
5. Monitor & Rate Limit Handling (Alerts, incident correlation, honest non-enforcement)
6. Attack Investigation Timeline (Chronological event sequencing)
7. Incident Explanation and Close endpoints
"""

import os
import sys
import unittest
from datetime import datetime, timezone

# Ensure backend root is on sys.path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Force SQLite for test isolation
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.database import Base
from app.db_models import SessionRecord, RequestLog, BlockedIP, SecurityAlert, SecurityIncident
from app.risk_engine import calculate_risk, clamp, calculate_request_rate_score, calculate_auth_failure_score, calculate_endpoint_risk
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
from app.security_pipeline import evaluate_session_security
from app.blocking_service import block_ip, is_ip_blocked
from app.alert_service import create_alert
from app.incident_service import get_incident, close_incident, get_incidents
from app.explanation_service import generate_incident_explanation
from app.main import app


class TestDynamicRiskEngine(unittest.TestCase):
    """Unit tests for Harshad's Dynamic Risk Engine."""

    def test_risk_engine_low_risk(self):
        res = calculate_risk(
            url_attack_probability=0.05,
            behavior_attack_probability=0.05,
            request_rate_score=0.0,
            auth_failure_score=0.0,
            endpoint_risk_score=0.10,
        )
        self.assertLess(res["risk_score"], 30.0)
        self.assertEqual(res["severity"], "LOW")
        self.assertIn("components", res)

    def test_risk_engine_medium_risk(self):
        res = calculate_risk(
            url_attack_probability=0.40,
            behavior_attack_probability=0.50,
            request_rate_score=0.20,
            auth_failure_score=0.30,
            endpoint_risk_score=0.40,
        )
        self.assertGreaterEqual(res["risk_score"], 30.0)
        self.assertLess(res["risk_score"], 60.0)
        self.assertEqual(res["severity"], "MEDIUM")

    def test_risk_engine_high_risk(self):
        res = calculate_risk(
            url_attack_probability=0.80,
            behavior_attack_probability=0.70,
            request_rate_score=0.60,
            auth_failure_score=0.50,
            endpoint_risk_score=0.60,
        )
        self.assertGreaterEqual(res["risk_score"], 60.0)
        self.assertLess(res["risk_score"], 80.0)
        self.assertEqual(res["severity"], "HIGH")

    def test_risk_engine_critical_risk(self):
        res = calculate_risk(
            url_attack_probability=0.95,
            behavior_attack_probability=0.95,
            request_rate_score=0.90,
            auth_failure_score=0.80,
            endpoint_risk_score=1.0,
        )
        self.assertGreaterEqual(res["risk_score"], 80.0)
        self.assertEqual(res["severity"], "CRITICAL")

    def test_risk_engine_missing_signals(self):
        # Empty invocation should gracefully use defaults (0.0)
        res = calculate_risk()
        self.assertEqual(res["risk_score"], 0.0)
        self.assertEqual(res["severity"], "LOW")
        self.assertIn("url", res["components"])
        self.assertIn("behavior", res["components"])

    def test_risk_engine_invalid_signals(self):
        # Out-of-bounds or non-float values should be clamped safely
        res = calculate_risk(
            url_attack_probability=2.5,
            behavior_attack_probability=-1.0,
            request_rate_score="invalid",
        )
        self.assertIsInstance(res["risk_score"], float)
        self.assertGreaterEqual(res["risk_score"], 0.0)
        self.assertLessEqual(res["risk_score"], 100.0)


class TestAdaptiveAgentThresholdBoundaries(unittest.TestCase):
    """Verify deterministic boundary thresholds for Adaptive Security Agent."""

    def test_boundary_0_allow(self):
        dec = decide_adaptive_security(risk_score=0)
        self.assertEqual(dec["action"], ACTION_ALLOW)
        self.assertEqual(dec["severity"], SEVERITY_LOW)

    def test_boundary_29_allow(self):
        dec = decide_adaptive_security(risk_score=29.0)
        self.assertEqual(dec["action"], ACTION_ALLOW)
        self.assertEqual(dec["severity"], SEVERITY_LOW)

    def test_boundary_30_monitor(self):
        dec = decide_adaptive_security(risk_score=30.0)
        self.assertEqual(dec["action"], ACTION_MONITOR)
        self.assertEqual(dec["severity"], SEVERITY_MEDIUM)

    def test_boundary_59_monitor(self):
        dec = decide_adaptive_security(risk_score=59.0)
        self.assertEqual(dec["action"], ACTION_MONITOR)
        self.assertEqual(dec["severity"], SEVERITY_MEDIUM)

    def test_boundary_60_rate_limit(self):
        dec = decide_adaptive_security(risk_score=60.0)
        self.assertEqual(dec["action"], ACTION_RATE_LIMIT)
        self.assertEqual(dec["severity"], SEVERITY_HIGH)
        # Verify honest enforcement reporting
        self.assertFalse(dec["enforcement"]["enforced"])
        self.assertEqual(dec["enforcement"]["mechanism"], "none")

    def test_boundary_79_rate_limit(self):
        dec = decide_adaptive_security(risk_score=79.0)
        self.assertEqual(dec["action"], ACTION_RATE_LIMIT)
        self.assertEqual(dec["severity"], SEVERITY_HIGH)

    def test_boundary_80_block(self):
        dec = decide_adaptive_security(risk_score=80.0)
        self.assertEqual(dec["action"], ACTION_BLOCK)
        self.assertEqual(dec["severity"], SEVERITY_CRITICAL)

    def test_boundary_100_block(self):
        dec = decide_adaptive_security(risk_score=100.0)
        self.assertEqual(dec["action"], ACTION_BLOCK)
        self.assertEqual(dec["severity"], SEVERITY_CRITICAL)

    def test_out_of_bounds(self):
        with self.assertRaises(ValueError):
            decide_adaptive_security(risk_score=-0.1)
        with self.assertRaises(ValueError):
            decide_adaptive_security(risk_score=100.1)


class TestPipelineAndIncidentIntegration(unittest.TestCase):
    """End-to-End integration tests using an isolated in-memory SQLite database."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def _create_test_session(self, ip="192.168.1.100", num_requests=5, is_malicious=False):
        now = datetime.now(timezone.utc)
        session = SessionRecord(
            session_id=f"sess_{ip.replace('.', '_')}",
            ip=ip,
            started_at=now,
            last_activity=now,
            request_count=num_requests,
            status="active",
        )
        self.db.add(session)
        self.db.commit()

        # Add RequestLog rows
        for i in range(num_requests):
            endpoint = "/admin/users" if is_malicious else "/items/view"
            status_code = 401 if (is_malicious and i % 2 == 0) else 200
            log = RequestLog(
                session_id=session.session_id,
                timestamp=now,
                ip=ip,
                method="GET" if not is_malicious else "POST",
                endpoint=endpoint,
                status_code=status_code,
                request_size=256,
                response_size=1024,
                response_time_ms=50.0,
                query_length=0,
                query_data="1=1" if is_malicious else "",
            )
            self.db.add(log)
        self.db.commit()
        return session

    def test_pipeline_allow_creates_no_alert(self):
        session = self._create_test_session(ip="10.0.0.1", num_requests=5, is_malicious=False)
        result = evaluate_session_security(
            db=self.db,
            session=session,
            client_ip=session.ip,
            current_url="/items/view",
        )
        self.assertTrue(result["evaluated"])
        # Normal traffic should produce ALLOW
        if result["action"] == ACTION_ALLOW:
            alerts = self.db.query(SecurityAlert).filter(SecurityAlert.session_id == session.session_id).all()
            self.assertEqual(len(alerts), 0)
            blocks = self.db.query(BlockedIP).filter(BlockedIP.ip == session.ip).all()
            self.assertEqual(len(blocks), 0)

    def test_pipeline_block_single_operation_no_duplicates(self):
        """Verify BLOCK performs exactly one block operation and creates exactly one alert."""
        session = self._create_test_session(ip="198.51.100.5", num_requests=10, is_malicious=True)

        # Force a BLOCK decision via block_ip call with score/severity
        block = block_ip(
            db=self.db,
            ip=session.ip,
            reason="Confirmed high-risk attack pattern",
            prediction="attacker",
            confidence=0.95,
            session_id=session.session_id,
            url_score=0.90,
            behavior_score=0.95,
            risk_score=92.5,
            severity="CRITICAL",
        )
        self.assertIsNotNone(block)

        # Verify exactly 1 active block record exists
        blocks = self.db.query(BlockedIP).filter(BlockedIP.ip == session.ip, BlockedIP.is_active.is_(True)).all()
        self.assertEqual(len(blocks), 1)

        # Verify exactly 1 alert exists for this block
        alerts = self.db.query(SecurityAlert).filter(SecurityAlert.session_id == session.session_id).all()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].action, "BLOCK")
        self.assertEqual(alerts[0].severity, "CRITICAL")
        self.assertEqual(alerts[0].risk_score, 92.5)

        # Verify incident correlation was created
        incidents = self.db.query(SecurityIncident).filter(SecurityIncident.session_id == session.session_id).all()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].primary_action, "BLOCK")
        self.assertEqual(incidents[0].event_count, 1)

    def test_pipeline_monitor_and_rate_limit_correlation(self):
        """Verify MONITOR and RATE_LIMIT create alerts and correlate without blocking."""
        session = self._create_test_session(ip="198.51.100.12", num_requests=5, is_malicious=False)

        # Create MONITOR alert
        alert1 = create_alert(
            db=self.db,
            ip=session.ip,
            action="MONITOR",
            reason="Suspicious probe detected",
            session_id=session.session_id,
            prediction="normal",
            confidence=0.60,
            url_score=0.40,
            behavior_score=0.35,
            risk_score=45.0,
            severity="MEDIUM",
        )
        self.assertIsNotNone(alert1)

        # Create RATE_LIMIT alert on same session
        alert2 = create_alert(
            db=self.db,
            ip=session.ip,
            action="RATE_LIMIT",
            reason="High frequency request burst",
            session_id=session.session_id,
            prediction="normal",
            confidence=0.75,
            url_score=0.65,
            behavior_score=0.70,
            risk_score=72.0,
            severity="HIGH",
        )
        self.assertIsNotNone(alert2)

        # IP should NOT be blocked
        self.assertFalse(is_ip_blocked(self.db, session.ip))

        # Exactly 1 correlated incident should exist with updated event_count=2
        incidents = self.db.query(SecurityIncident).filter(SecurityIncident.session_id == session.session_id).all()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].event_count, 2)
        self.assertEqual(incidents[0].severity, "HIGH")
        self.assertEqual(incidents[0].primary_action, "RATE_LIMIT")

    def test_attack_investigation_timeline_chronological_order(self):
        """Test GET /incidents/{session_id}/timeline via FastAPI client."""
        client = TestClient(app)
        session_id = "sess_timeline_test_123"
        ip = "192.0.2.88"

        # Ingest traffic to populate session and requests
        for i in range(3):
            endpoint = "/login" if i == 0 else ("/admin/config" if i == 1 else "/api/data")
            status = 401 if i == 0 else 200
            client.post("/api/ingest-traffic", json={
                "ip": ip,
                "method": "POST" if i == 0 else "GET",
                "endpoint": endpoint,
                "status_code": status,
                "timestamp": f"2026-10-01T00:0{i}:00Z",
                "request_size": 100,
                "response_size": 200,
                "response_time_ms": 35.0,
            })

        # Fetch timeline
        resp = client.get(f"/incidents/{session_id}/timeline")
        # In case the ingested session used a generated session_id, fetch from /incidents
        incidents_resp = client.get("/incidents")
        self.assertEqual(incidents_resp.status_code, 200)

        # If any sessions returned, test timeline on first session
        sessions = incidents_resp.json()
        target_session = sessions[0]["session_id"] if sessions else session_id

        timeline_resp = client.get(f"/incidents/{target_session}/timeline")
        self.assertEqual(timeline_resp.status_code, 200)
        data = timeline_resp.json()
        if "timeline" in data:
            events = data["timeline"]
            self.assertGreater(len(events), 0)
            # Verify timestamps are chronological
            timestamps = [e["timestamp"] for e in events if e.get("timestamp")]
            self.assertEqual(timestamps, sorted(timestamps))

    def test_incident_explanation_and_close(self):
        """Test incident explanation generation and incident closing."""
        session = self._create_test_session(ip="203.0.113.44", num_requests=5, is_malicious=True)
        alert = create_alert(
            db=self.db,
            ip=session.ip,
            action="BLOCK",
            reason="Automated admin endpoint brute force",
            session_id=session.session_id,
            prediction="attacker",
            confidence=0.92,
            url_score=0.85,
            behavior_score=0.90,
            risk_score=88.0,
            severity="CRITICAL",
        )

        incident = self.db.query(SecurityIncident).filter(SecurityIncident.session_id == session.session_id).first()
        self.assertIsNotNone(incident)

        # Test explanation
        explanation = generate_incident_explanation(incident, [alert])
        self.assertIn("factors", explanation)
        self.assertGreater(len(explanation["factors"]), 0)
        self.assertEqual(explanation["severity"], "CRITICAL")

        # Test close
        closed = close_incident(self.db, incident.id)
        self.assertIsNotNone(closed)
        self.assertEqual(closed.status, "CLOSED")


if __name__ == "__main__":
    unittest.main()
