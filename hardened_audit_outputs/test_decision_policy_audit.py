"""
Phase 3 — Post-Hardening Automated Decision-Policy & Boundary Test Suite
Tests every decision threshold, boundary, non-finite input, missing evidence,
and failure behavior against the active hardened Chakravyuh Sentinel implementation.
Outputs hardened_audit_outputs/policy_test_cases.csv and prints results.
"""

import os
import sys
import csv
import math
import unittest
from datetime import datetime, timezone

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "chakrahvyuh-sentinel", "HANDOVER", "HANDOVER", "chakravyuh_backend"))
sys.path.insert(0, BACKEND_DIR)

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, SessionLocal, engine
from app.risk_engine import (
    calculate_risk,
    clamp,
    calculate_request_rate_score,
    calculate_auth_failure_score,
    calculate_endpoint_risk,
)
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
from app.db_models import BlockedIP, SecurityAlert, SessionRecord, RequestLog
from app.blocking_service import block_ip, is_ip_blocked
from app.security_pipeline import evaluate_session_security

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

test_records = []

def record_test(test_id, category, input_summary, expected_outcome, actual_outcome, status, source_ref, notes=""):
    test_records.append({
        "test_id": test_id,
        "category": category,
        "input_preconditions": input_summary,
        "expected_outcome": expected_outcome,
        "actual_outcome": actual_outcome,
        "status": status,
        "source_reference": source_ref,
        "notes": notes,
    })

def run_all_policy_tests():
    Base.metadata.create_all(bind=engine)
    agent = AdaptiveSecurityAgent()
    print("[*] Running Post-Hardening Decision Policy & Boundary Tests...")

    # -------------------------------------------------------------
    # 1. Exact Threshold & Boundary Tests
    # -------------------------------------------------------------
    boundary_cases = [
        ("POL-01", -0.1, "ValueError", "Out-of-range negative score"),
        ("POL-02", 0.0, (ACTION_ALLOW, SEVERITY_LOW), "Exact minimum boundary"),
        ("POL-03", 15.0, (ACTION_ALLOW, SEVERITY_LOW), "Mid-range ALLOW score"),
        ("POL-04", 28.9, (ACTION_ALLOW, SEVERITY_LOW), "Immediately below allow_max (29)"),
        ("POL-05", 29.0, (ACTION_ALLOW, SEVERITY_LOW), "Exact allow_max threshold"),
        ("POL-06", 29.1, (ACTION_MONITOR, SEVERITY_MEDIUM), "Immediately above allow_max (29)"),
        ("POL-07", 29.9, (ACTION_MONITOR, SEVERITY_MEDIUM), "Fractional score below 30"),
        ("POL-08", 30.0, (ACTION_MONITOR, SEVERITY_MEDIUM), "Exact monitor_min threshold"),
        ("POL-09", 45.0, (ACTION_MONITOR, SEVERITY_MEDIUM), "Mid-range MONITOR score"),
        ("POL-10", 58.9, (ACTION_MONITOR, SEVERITY_MEDIUM), "Immediately below monitor_max (59)"),
        ("POL-11", 59.0, (ACTION_MONITOR, SEVERITY_MEDIUM), "Exact monitor_max threshold"),
        ("POL-12", 59.1, (ACTION_RATE_LIMIT, SEVERITY_HIGH), "Immediately above monitor_max (59)"),
        ("POL-13", 60.0, (ACTION_RATE_LIMIT, SEVERITY_HIGH), "Exact rate_limit_min threshold"),
        ("POL-14", 70.0, (ACTION_RATE_LIMIT, SEVERITY_HIGH), "Mid-range RATE_LIMIT score"),
        ("POL-15", 78.9, (ACTION_RATE_LIMIT, SEVERITY_HIGH), "Immediately below rate_limit_max (79)"),
        ("POL-16", 79.0, (ACTION_RATE_LIMIT, SEVERITY_HIGH), "Exact rate_limit_max threshold"),
        ("POL-17", 79.1, (ACTION_BLOCK, SEVERITY_CRITICAL), "Immediately above rate_limit_max (79)"),
        ("POL-18", 80.0, (ACTION_BLOCK, SEVERITY_CRITICAL), "Exact block_min threshold"),
        ("POL-19", 90.0, (ACTION_BLOCK, SEVERITY_CRITICAL), "Mid-range BLOCK score"),
        ("POL-20", 100.0, (ACTION_BLOCK, SEVERITY_CRITICAL), "Exact maximum boundary"),
        ("POL-21", 100.1, "ValueError", "Out-of-range positive score"),
    ]

    for tid, score, expected, desc in boundary_cases:
        src = "app/adaptive_agent.py#L286-L294"
        if expected == "ValueError":
            try:
                agent.decide(score)
                record_test(tid, "Boundary", f"risk_score={score} ({desc})", "Raises ValueError", "No exception raised", "FAIL", src)
            except ValueError as e:
                record_test(tid, "Boundary", f"risk_score={score} ({desc})", "Raises ValueError", f"ValueError: {e}", "PASS", src)
            except Exception as e:
                record_test(tid, "Boundary", f"risk_score={score} ({desc})", "Raises ValueError", f"Unexpected: {type(e).__name__}", "FAIL", src)
        else:
            exp_action, exp_sev = expected
            try:
                res = agent.decide(score)
                act_action = res["action"]
                act_sev = res["severity"]
                passed = (act_action == exp_action and act_sev == exp_sev)
                record_test(
                    tid,
                    "Boundary",
                    f"risk_score={score} ({desc})",
                    f"action={exp_action}, severity={exp_sev}",
                    f"action={act_action}, severity={act_sev}",
                    "PASS" if passed else "FAIL",
                    src
                )
            except Exception as e:
                record_test(tid, "Boundary", f"risk_score={score} ({desc})", f"action={exp_action}, severity={exp_sev}", f"Crashed: {e}", "FAIL", src)

    # -------------------------------------------------------------
    # 2. Validation & Edge Cases (None, NaN, Inf, String, Boolean)
    # -------------------------------------------------------------
    val_cases = [
        ("VAL-01", None, "ValueError", "None risk_score"),
        ("VAL-02", float("nan"), "ValueError", "NaN risk_score"),
        ("VAL-03", float("inf"), "ValueError", "Positive infinity risk_score"),
        ("VAL-04", float("-inf"), "ValueError", "Negative infinity risk_score"),
        ("VAL-05", "85", "TypeError", "String risk_score ('85')"),
        ("VAL-06", True, "TypeError", "Boolean risk_score (True)"),
        ("VAL-07", False, "TypeError", "Boolean risk_score (False)"),
    ]

    for tid, val, exp_err, desc in val_cases:
        src = "app/adaptive_agent.py#L102-L121"
        try:
            agent.decide(val)
            record_test(tid, "Validation", f"risk_score={val} ({desc})", f"Raises {exp_err}", "No exception raised", "FAIL", src)
        except ValueError as e:
            st = "PASS" if exp_err == "ValueError" else "FAIL"
            record_test(tid, "Validation", f"risk_score={val} ({desc})", f"Raises {exp_err}", f"ValueError: {e}", st, src)
        except TypeError as e:
            st = "PASS" if exp_err == "TypeError" else "FAIL"
            record_test(tid, "Validation", f"risk_score={val} ({desc})", f"Raises {exp_err}", f"TypeError: {e}", st, src)
        except Exception as e:
            record_test(tid, "Validation", f"risk_score={val} ({desc})", f"Raises {exp_err}", f"Unexpected: {type(e).__name__}", "FAIL", src)

    # Confidence validation
    conf_cases = [
        ("VAL-08", 50.0, -0.01, "ValueError", "Negative confidence (-0.01)"),
        ("VAL-09", 50.0, 1.01, "ValueError", "Excessive confidence (1.01)"),
        ("VAL-10", 50.0, "high", "TypeError", "String confidence ('high')"),
        ("VAL-11", 50.0, float("nan"), "ValueError", "NaN confidence"),
    ]
    for tid, score, conf, exp_err, desc in conf_cases:
        src = "app/adaptive_agent.py#L123-L132"
        try:
            agent.decide(score, confidence=conf)
            record_test(tid, "Validation", f"score={score}, confidence={conf} ({desc})", f"Raises {exp_err}", "No exception raised", "FAIL", src)
        except ValueError as e:
            st = "PASS" if exp_err == "ValueError" else "FAIL"
            record_test(tid, "Validation", f"score={score}, confidence={conf} ({desc})", f"Raises {exp_err}", f"ValueError: {e}", st, src)
        except TypeError as e:
            st = "PASS" if exp_err == "TypeError" else "FAIL"
            record_test(tid, "Validation", f"score={score}, confidence={conf} ({desc})", f"Raises {exp_err}", f"TypeError: {e}", st, src)
        except Exception as e:
            record_test(tid, "Validation", f"score={score}, confidence={conf} ({desc})", f"Raises {exp_err}", f"Unexpected: {type(e).__name__}", "FAIL", src)

    # -------------------------------------------------------------
    # 3. Dynamic Risk Engine Component Clamping & Sub-functions
    # -------------------------------------------------------------
    src_re = "app/risk_engine.py"

    # Default empty
    r_empty = calculate_risk()
    st = "PASS" if r_empty["risk_score"] == 0.0 and r_empty["severity"] == "LOW" else "FAIL"
    record_test("ENG-01", "Risk Engine", "calculate_risk() with no args", "risk_score=0.0, severity=LOW", f"risk_score={r_empty['risk_score']}, severity={r_empty['severity']}", st, f"{src_re}#L60-L111")

    # Clamping extreme negative
    r_neg = calculate_risk(url_attack_probability=-5.0, behavior_attack_probability=-2.0)
    st = "PASS" if r_neg["risk_score"] == 0.0 else "FAIL"
    record_test("ENG-02", "Risk Engine", "Sub-scores = -5.0, -2.0", "Clamped to 0.0 -> risk_score=0.0", f"risk_score={r_neg['risk_score']}", st, f"{src_re}#L14-L20")

    # Clamping extreme positive
    r_pos = calculate_risk(
        url_attack_probability=2.0,
        behavior_attack_probability=5.0,
        request_rate_score=1.5,
        auth_failure_score=1.2,
        endpoint_risk_score=2.0
    )
    st = "PASS" if r_pos["risk_score"] == 100.0 and r_pos["severity"] == "CRITICAL" else "FAIL"
    record_test("ENG-03", "Risk Engine", "All sub-scores >= 2.0 (overflow)", "Clamped to 1.0 -> risk_score=100.0", f"risk_score={r_pos['risk_score']}, severity={r_pos['severity']}", st, f"{src_re}#L14-L20")

    # Rate calculation sub-tests
    r_rate_0 = calculate_request_rate_score(0.0)
    record_test("ENG-04", "Risk Engine", "max_requests_per_second=0.0 (Rate <= 2 req/s -> 0.0)", "score=0.0", f"score={r_rate_0}", "PASS" if r_rate_0 == 0.0 else "FAIL", f"{src_re}#L22-L38")

    r_rate_2 = calculate_request_rate_score(2.0)
    record_test("ENG-05", "Risk Engine", "max_requests_per_second=2.0 (Rate == 2 req/s -> 0.0)", "score=0.0", f"score={r_rate_2}", "PASS" if r_rate_2 == 0.0 else "FAIL", f"{src_re}#L22-L38")

    r_rate_mid = calculate_request_rate_score(11.0)
    record_test("ENG-06", "Risk Engine", "max_requests_per_second=11.0 (Rate == 11 req/s -> (11-2)/18 = 0.50)", "score=0.5", f"score={r_rate_mid}", "PASS" if abs(r_rate_mid - 0.5) < 1e-4 else "FAIL", f"{src_re}#L22-L38")

    r_rate_20 = calculate_request_rate_score(20.0)
    record_test("ENG-07", "Risk Engine", "max_requests_per_second=20.0 (Rate == 20 req/s -> 1.0)", "score=1.0", f"score={r_rate_20}", "PASS" if r_rate_20 == 1.0 else "FAIL", f"{src_re}#L22-L38")

    r_rate_max = calculate_request_rate_score(50.0)
    record_test("ENG-08", "Risk Engine", "max_requests_per_second=50.0 (Rate > 20 req/s -> 1.0)", "score=1.0", f"score={r_rate_max}", "PASS" if r_rate_max == 1.0 else "FAIL", f"{src_re}#L22-L38")

    r_rate_str = calculate_request_rate_score("invalid")
    record_test("ENG-09", "Risk Engine", "max_requests_per_second=invalid (Malformed string rate -> 0.0)", "score=0.0", f"score={r_rate_str}", "PASS" if r_rate_str == 0.0 else "FAIL", f"{src_re}#L22-L38")

    # Endpoint sensitivity tests
    ep_admin = calculate_endpoint_risk("/admin/users")
    record_test("ENG-10", "Risk Engine", "endpoint='/admin/users' (/admin route)", "score=1.0", f"score={ep_admin}", "PASS" if ep_admin == 1.0 else "FAIL", f"{src_re}#L43-L59")

    ep_login = calculate_endpoint_risk("/api/auth/login")
    record_test("ENG-11", "Risk Engine", "endpoint='/api/auth/login' (/login route)", "score=0.6", f"score={ep_login}", "PASS" if ep_login == 0.6 else "FAIL", f"{src_re}#L43-L59")

    ep_acc = calculate_endpoint_risk("/user/account/settings")
    record_test("ENG-12", "Risk Engine", "endpoint='/user/account/settings' (/account route takes precedence over /user)", "score=0.5", f"score={ep_acc}", "PASS" if ep_acc == 0.5 else "FAIL", f"{src_re}#L43-L59")

    ep_user = calculate_endpoint_risk("/user/profile")
    record_test("ENG-13", "Risk Engine", "endpoint='/user/profile' (/user route)", "score=0.4", f"score={ep_user}", "PASS" if ep_user == 0.4 else "FAIL", f"{src_re}#L43-L59")

    ep_def = calculate_endpoint_risk("/api/services")
    record_test("ENG-14", "Risk Engine", "endpoint='/api/services' (Default route)", "score=0.1", f"score={ep_def}", "PASS" if ep_def == 0.1 else "FAIL", f"{src_re}#L43-L59")

    ep_empty = calculate_endpoint_risk("")
    record_test("ENG-15", "Risk Engine", "endpoint='' (Empty endpoint string)", "score=0.1", f"score={ep_empty}", "PASS" if ep_empty == 0.1 else "FAIL", f"{src_re}#L43-L59")

    # Hardening validation: NaN & Inf rejection tests
    try:
        calculate_risk(url_attack_probability=float("nan"))
        record_test("ENG-16", "Risk Engine Hardening", "url_attack_probability=NaN", "Raises ValueError", "No exception raised", "FAIL", f"{src_re}#L60-L90")
    except ValueError as e:
        record_test("ENG-16", "Risk Engine Hardening", "url_attack_probability=NaN", "Raises ValueError", f"ValueError: {e}", "PASS", f"{src_re}#L60-L90")

    try:
        calculate_risk(behavior_attack_probability=float("inf"))
        record_test("ENG-17", "Risk Engine Hardening", "behavior_attack_probability=Inf", "Raises ValueError", "No exception raised", "FAIL", f"{src_re}#L60-L90")
    except ValueError as e:
        record_test("ENG-17", "Risk Engine Hardening", "behavior_attack_probability=Inf", "Raises ValueError", f"ValueError: {e}", "PASS", f"{src_re}#L60-L90")

    try:
        clamp(float("nan"), name="test_val")
        record_test("ENG-18", "Risk Engine Hardening", "clamp(NaN)", "Raises ValueError", "No exception raised", "FAIL", f"{src_re}#L14-L25")
    except ValueError as e:
        record_test("ENG-18", "Risk Engine Hardening", "clamp(NaN)", "Raises ValueError", f"ValueError: {e}", "PASS", f"{src_re}#L14-L25")

    try:
        calculate_request_rate_score(float("nan"))
        record_test("ENG-19", "Risk Engine Hardening", "calculate_request_rate_score(NaN)", "Raises ValueError", "No exception raised", "FAIL", f"{src_re}#L22-L38")
    except ValueError as e:
        record_test("ENG-19", "Risk Engine Hardening", "calculate_request_rate_score(NaN)", "Raises ValueError", f"ValueError: {e}", "PASS", f"{src_re}#L22-L38")

    # -------------------------------------------------------------
    # 4. Enforcement Honesty Tests
    # -------------------------------------------------------------
    # RATE_LIMIT honesty test
    rl_decision = agent.decide(70.0)
    rl_honesty_pass = (rl_decision["enforcement"]["enforced"] is False and rl_decision["enforcement"]["mechanism"] == "none")
    record_test("ENF-01", "Enforcement Honesty", "risk_score=70.0 (RATE_LIMIT)", "enforced=False, mechanism='none'", f"enforced={rl_decision['enforcement']['enforced']}, mechanism='{rl_decision['enforcement']['mechanism']}'", "PASS" if rl_honesty_pass else "FAIL", "app/adaptive_agent.py#L305-L311", "Verifies rate limiting is not fraudulently claimed as active gateway enforcement")

    # BLOCK side-effect-free by default
    block_default = agent.decide(85.0, enforce_block=False)
    block_default_pass = (block_default["enforcement"]["enforced"] is False)
    record_test("ENF-02", "Enforcement Honesty", "risk_score=85.0 with enforce_block=False", "enforced=False (no side-effects)", f"enforced={block_default['enforcement']['enforced']}", "PASS" if block_default_pass else "FAIL", "app/adaptive_agent.py#L356-L361")

    # BLOCK active enforcement when requested with DB
    db = SessionLocal()
    test_ip = "192.168.99.1"
    try:
        block_active = agent.decide(85.0, enforce_block=True, db=db, source_ip=test_ip)
        blocked_in_db = is_ip_blocked(db, test_ip)
        block_active_pass = (block_active["enforcement"]["enforced"] is True and blocked_in_db)
        record_test("ENF-03", "Enforcement Honesty", "risk_score=85.0 with enforce_block=True & db", "enforced=True, IP in blocked_ips", f"enforced={block_active['enforcement']['enforced']}, is_blocked={blocked_in_db}", "PASS" if block_active_pass else "FAIL", "app/adaptive_agent.py#L313-L347")
    finally:
        db.close()

    # -------------------------------------------------------------
    # 5. Explainability Verification
    # -------------------------------------------------------------
    exp_admin = agent.decide(85.0, context={"admin_endpoint_access": 3})
    has_admin_reason = any("admin endpoint probe" in r.lower() for r in exp_admin["reasons"])
    record_test("EXP-01", "Explainability", "context={'admin_endpoint_access': 3}", "Reasons mention admin endpoint probe", f"reasons={exp_admin['reasons']}", "PASS" if has_admin_reason else "FAIL", "app/adaptive_agent.py#L201-L207")

    exp_auth = agent.decide(75.0, context={"auth_failure_ratio": 0.40})
    has_auth_reason = any("authentication failure" in r.lower() for r in exp_auth["reasons"])
    record_test("EXP-02", "Explainability", "context={'auth_failure_ratio': 0.40}", "Reasons mention authentication failure ratio", f"reasons={exp_auth['reasons']}", "PASS" if has_auth_reason else "FAIL", "app/adaptive_agent.py#L193-L199")

    exp_clean = agent.decide(92.0, context={})
    no_fake_claim = not any("confirmed attack" in r.lower() for r in exp_clean["reasons"])
    record_test("EXP-03", "Explainability", "context={} (no upstream confirmation)", "Reasons state BLOCK threshold reached, NOT confirmed attack", f"reasons={exp_clean['reasons']}", "PASS" if no_fake_claim else "FAIL", "app/adaptive_agent.py#L213-L218")

    # -------------------------------------------------------------
    # 6. Save Artifacts
    # -------------------------------------------------------------
    csv_path = os.path.join(OUTPUT_DIR, "policy_test_cases.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(test_records[0].keys()))
        writer.writeheader()
        writer.writerows(test_records)
    print(f"[+] Saved {len(test_records)} post-hardening policy test cases to: {csv_path}")

    passed_count = sum(1 for t in test_records if t["status"] == "PASS")
    failed_count = sum(1 for t in test_records if t["status"] == "FAIL")
    print(f"[*] Policy Test Results: {passed_count} PASSED, {failed_count} FAILED out of {len(test_records)} total.")

if __name__ == "__main__":
    run_all_policy_tests()
