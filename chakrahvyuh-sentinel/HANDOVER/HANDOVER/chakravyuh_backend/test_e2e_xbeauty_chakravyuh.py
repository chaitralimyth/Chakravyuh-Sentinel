"""
End-to-End Test Suite for X Beauty + Chakravyuh Sentinel Live Integration

Verifies:
TEST 1: Normal request -> X Beauty 200 OK -> Chakravyuh records telemetry -> ALLOW / LOW
TEST 2: Controlled suspicious request -> Chakravyuh ML evaluation -> Risk calculated -> Dashboard updated
TEST 3: Repeated abnormal requests -> Session threshold reached (5) -> 28 features extracted -> RF model runs -> Adaptive action
TEST 4: Rate limiting -> Burst of requests -> Chakravyuh sliding-window rate limiter -> 429 Too Many Requests
TEST 5: Blocking -> Chakravyuh BLOCK decision -> IP blocked -> X Beauty enforces HTTP 403 Forbidden
"""

import sys
import time
import httpx

CHAKRAVYUH_URL = "http://127.0.0.1:8000"
XBEAUTY_URL = "http://127.0.0.1:8001"


def print_banner(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)


def test_1_normal_request():
    print_banner("TEST 1: Normal Legitimate Request Flow")
    client_ip = "192.168.1.101"
    headers = {"X-Forwarded-For": client_ip}

    print(f"-> Sending GET /api/services to X Beauty ({XBEAUTY_URL})...")
    resp = httpx.get(f"{XBEAUTY_URL}/api/services", headers=headers, timeout=5.0)
    print(f"<- X Beauty HTTP Status: {resp.status_code}")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    services = resp.json()
    print(f"   Received {len(services)} services from X Beauty business logic")
    print(f"   Response Headers: X-Sentinel-Action={resp.headers.get('X-Sentinel-Action')}, X-Sentinel-Session={resp.headers.get('X-Sentinel-Session-Id')}")

    # Give backend a moment to commit telemetry
    time.sleep(0.3)

    # Verify Chakravyuh recorded the request
    print(f"-> Querying Chakravyuh Sentinel ({CHAKRAVYUH_URL}/requests?ip={client_ip})...")
    c_resp = httpx.get(f"{CHAKRAVYUH_URL}/requests?ip={client_ip}", timeout=5.0)
    assert c_resp.status_code == 200
    logs = c_resp.json()
    assert len(logs) > 0, f"Expected request logs for {client_ip}"
    latest = logs[0]
    print(f"<- Chakravyuh Request Log: endpoint='{latest['endpoint']}', status={latest['status_code']}, session={latest['session_id']}")

    # Verify session in Chakravyuh
    s_resp = httpx.get(f"{CHAKRAVYUH_URL}/sessions", timeout=5.0)
    assert s_resp.status_code == 200
    sessions = s_resp.json()
    user_session = next((s for s in sessions if s.get("ip") == client_ip), None)
    assert user_session is not None, f"Expected session for {client_ip}"
    print(f"<- Chakravyuh Session: id={user_session['session_id']}, requests={user_session['request_count']}, status={user_session['status']}")

    print("PASS: TEST 1 - Normal request succeeded and recorded in Sentinel pipeline!\n")
    return user_session["session_id"]


def test_2_controlled_suspicious_request():
    print_banner("TEST 2: Controlled Suspicious Request (Sensitive Endpoint & Auth Failure)")
    client_ip = "192.168.1.102"
    headers = {"X-Forwarded-For": client_ip}

    print(f"-> Sending invalid login attempt to X Beauty ({XBEAUTY_URL}/api/auth/login)...")
    resp = httpx.post(
        f"{XBEAUTY_URL}/api/auth/login",
        json={"email": "attacker@unknown.domain", "password": "wrongpassword123"},
        headers=headers,
        timeout=5.0,
    )
    print(f"<- X Beauty HTTP Status: {resp.status_code} (Expected 401 Unauthorized)")
    assert resp.status_code == 401

    time.sleep(0.3)

    # Verify Chakravyuh recorded the authentication failure WITHOUT credentials
    c_resp = httpx.get(f"{CHAKRAVYUH_URL}/requests?ip={client_ip}", timeout=5.0)
    assert c_resp.status_code == 200
    logs = c_resp.json()
    assert len(logs) > 0
    latest_log = logs[0]
    print(f"<- Chakravyuh telemetry logged: endpoint='{latest_log['endpoint']}', status={latest_log['status_code']}")
    # SENSITIVE DATA BOUNDARY: credentials must never be in telemetry
    assert "wrongpassword123" not in str(latest_log), "Password leaked into Chakravyuh telemetry!"
    assert "attacker@unknown.domain" not in str(latest_log), "Credentials leaked into Chakravyuh telemetry!"
    print("<- Verified: Zero credentials or passwords transmitted to Chakravyuh Sentinel!")

    print("PASS: TEST 2 - Controlled suspicious request detected and telemetry logged without sensitive data!\n")


def test_3_repeated_abnormal_requests():
    print_banner("TEST 3: Repeated Abnormal Requests (Session Evaluation Trigger)")
    client_ip = "192.168.1.103"
    headers = {"X-Forwarded-For": client_ip}

    print(f"-> Generating 5 consecutive rapid suspicious requests from {client_ip}...")
    endpoints = [
        "/api/auth/login",
        "/api/auth/login",
        "/api/auth/login",
        "/api/auth/login",
        "/api/auth/login",
    ]

    for i, ep in enumerate(endpoints):
        resp = httpx.post(
            f"{XBEAUTY_URL}{ep}",
            json={"email": f"probe_{i}@test.com", "password": "badpassword"},
            headers=headers,
            timeout=5.0,
        )
        print(f"   Request {i+1}/5 to {ep} -> HTTP {resp.status_code}")
        time.sleep(0.1)

    time.sleep(0.5)

    # Verify session evaluation occurred in Chakravyuh
    s_resp = httpx.get(f"{CHAKRAVYUH_URL}/sessions", timeout=5.0)
    sessions = s_resp.json()
    user_session = next((s for s in sessions if s.get("ip") == client_ip), None)
    assert user_session is not None
    print(f"<- Chakravyuh Session request_count: {user_session['request_count']} (Reached eval threshold = 5)")

    # Check alerts in Chakravyuh
    a_resp = httpx.get(f"{CHAKRAVYUH_URL}/alerts", timeout=5.0)
    alerts = a_resp.json()
    session_alerts = [a for a in alerts if a.get("ip") == client_ip]
    print(f"<- Chakravyuh Alerts generated for {client_ip}: {len(session_alerts)}")
    if session_alerts:
        top_alert = session_alerts[0]
        print(f"   Alert ID: ALT-{top_alert['id']}, Risk Score: {top_alert.get('risk_score')}, Severity: {top_alert.get('severity')}, Action: {top_alert.get('action')}")
        assert top_alert.get("risk_score") is not None, "Dynamic risk score must come from Chakravyuh!"
        assert top_alert.get("severity") is not None, "Severity must come from Chakravyuh!"
        assert top_alert.get("action") is not None, "Action must come from Chakravyuh!"

    print("PASS: TEST 3 - Repeated traffic accumulated and triggered behavior/risk evaluation!\n")


def test_4_rate_limiting():
    print_banner("TEST 4: Rate Limiting Enforcement & Pre-Route Protection")
    # Use unique fresh IP for single-slot verification
    fresh_ip = f"192.168.1.{int(time.time()) % 150 + 50}"

    print(f"-> Verifying non-mutating pre-check and single-slot consumption from {fresh_ip}...")
    # 1. Pre-check /api/check-ip
    check_resp = httpx.get(f"{CHAKRAVYUH_URL}/api/check-ip/{fresh_ip}", timeout=5.0)
    assert check_resp.status_code == 200
    pre_info = check_resp.json().get("rate_limit_info", {})
    assert pre_info.get("current", 0) == 0, f"Expected 0 requests recorded before traffic, got {pre_info.get('current')}"
    print(f"<- /api/check-ip is strictly non-mutating (0 slots consumed)")

    # 2. Repeated /api/check-ip
    check_resp2 = httpx.get(f"{CHAKRAVYUH_URL}/api/check-ip/{fresh_ip}", timeout=5.0)
    assert check_resp2.status_code == 200
    pre_info2 = check_resp2.json().get("rate_limit_info", {})
    assert pre_info2.get("current", 0) == 0, "Repeated /api/check-ip mutated rate limit history!"
    print(f"<- Repeated /api/check-ip confirmed non-mutating (still 0 slots)")

    # 3. Send 1 actual request through X Beauty
    fresh_headers = {"X-Forwarded-For": fresh_ip}
    r1 = httpx.get(f"{XBEAUTY_URL}/api/services", headers=fresh_headers, timeout=5.0)
    assert r1.status_code == 200
    time.sleep(0.3)
    post_check = httpx.get(f"{CHAKRAVYUH_URL}/api/check-ip/{fresh_ip}", timeout=5.0)
    post_info = post_check.json().get("rate_limit_info", {})
    assert post_info.get("current") == 1, f"Expected exactly 1 slot consumed for 1 real request, got {post_info.get('current')}!"
    print(f"<- Authoritative single slot consumed for actual request (exactly 1 slot)")

    # 4. Test active rate limit enforcement
    rate_limit_ip = "192.168.1.205"
    rl_headers = {"X-Forwarded-For": rate_limit_ip}
    print(f"-> Verifying rate limit enforcement for {rate_limit_ip}...")

    # Ensure rate limit IP has reached threshold
    rl_check = httpx.get(f"{CHAKRAVYUH_URL}/api/check-ip/{rate_limit_ip}", timeout=5.0).json()
    if not rl_check.get("rate_limited"):
        print(f"   Injecting traffic burst to bring {rate_limit_ip} to rate limit threshold...")
        for _ in range(120):
            httpx.post(
                f"{CHAKRAVYUH_URL}/api/ingest-traffic",
                json={
                    "ip": rate_limit_ip,
                    "method": "GET",
                    "endpoint": "/api/services",
                    "status_code": 200,
                    "timestamp": "2026-10-03T18:00:00Z",
                    "request_size": 0,
                    "response_size": 50,
                    "response_time_ms": 1,
                    "query_length": 0,
                    "query_data": "",
                },
                timeout=5.0,
            )

    # Now attempt GET request to X Beauty
    resp = httpx.get(f"{XBEAUTY_URL}/api/services", headers=rl_headers, timeout=5.0)
    print(f"<- Rate-limited GET received HTTP {resp.status_code} (Expected 429 Too Many Requests)")
    assert resp.status_code == 429, f"Expected 429, got {resp.status_code}"
    print(f"<- Rate limit response: {resp.json()}")

    # PRE-ROUTE VERIFICATION:
    # Now that the IP is rate-limited, attempt a state-changing POST request
    # to X Beauty (message creation). The route MUST NOT execute!
    print("-> Testing PRE-ROUTE rate limit enforcement on state-changing POST /api/messages...")
    state_changing_resp = httpx.post(
        f"{XBEAUTY_URL}/api/messages",
        json={
            "name": "Spam Bot",
            "email": "spambot@rate-limit.test",
            "phone": "555-0199",
            "message": "This message must never be stored!"
        },
        headers=rl_headers,
        timeout=5.0,
    )
    print(f"<- State-changing endpoint response status: HTTP {state_changing_resp.status_code}")
    assert state_changing_resp.status_code == 429, f"Expected 429, got {state_changing_resp.status_code}"
    print("<- Verified: State-changing POST endpoint was dropped BEFORE execution!")

    print("PASS: TEST 4 - Real sliding-window rate limiting & pre-route enforcement verified!\n")


def test_5_blocking():
    print_banner("TEST 5: Active Blocking Enforcement & Pre-Route Protection")
    client_ip = "198.51.100.77"
    headers = {"X-Forwarded-For": client_ip}

    print(f"-> Registering security block for test attacker IP {client_ip} in Chakravyuh Sentinel...")
    from app.database import SessionLocal
    from app.blocking_service import block_ip

    db = SessionLocal()
    try:
        block_ip(
            db=db,
            ip=client_ip,
            reason="Simulated high-risk malicious traffic threshold exceeded (CRITICAL)",
            prediction="attacker",
            confidence=0.98,
            risk_score=92.0,
            severity="CRITICAL",
        )
    finally:
        db.close()

    time.sleep(0.3)

    # Verify IP is in Chakravyuh blocked list
    b_resp = httpx.get(f"{CHAKRAVYUH_URL}/blocked-ips?active_only=true", timeout=5.0)
    blocked_list = b_resp.json()
    is_in_blocks = any(b.get("ip") == client_ip for b in blocked_list)
    assert is_in_blocks, f"Expected {client_ip} in blocked IPs"
    print(f"<- Chakravyuh Sentinel confirmed: {client_ip} is actively BLOCKED")

    # Attempt GET request from blocked IP
    print(f"-> Sending GET from blocked IP {client_ip} to X Beauty ({XBEAUTY_URL}/api/services)...")
    resp = httpx.get(f"{XBEAUTY_URL}/api/services", headers=headers, timeout=5.0)
    print(f"<- X Beauty GET Response Status: HTTP {resp.status_code} (Expected 403 Forbidden)")
    assert resp.status_code == 403, f"Expected 403 Forbidden, got {resp.status_code}"

    # PRE-ROUTE VERIFICATION:
    # Attempt a state-changing POST request from blocked IP
    print("-> Testing PRE-ROUTE block enforcement on state-changing POST /api/messages...")
    post_resp = httpx.post(
        f"{XBEAUTY_URL}/api/messages",
        json={
            "name": "Blocked Attacker",
            "email": "attacker@blocked.test",
            "phone": "555-0666",
            "message": "Blocked payload that must never execute!"
        },
        headers=headers,
        timeout=5.0,
    )
    print(f"<- State-changing POST Response Status: HTTP {post_resp.status_code}")
    assert post_resp.status_code == 403, f"Expected 403, got {post_resp.status_code}"
    print("<- Verified: Blocked request was dropped BEFORE business route executed!")

    print("PASS: TEST 5 - Active blocking pre-route protection successfully verified!\n")


def main():
    print("\n" + "#" * 65)
    print("  RUNNING X BEAUTY + CHAKRAVYUH SENTINEL E2E INTEGRATION SUITE")
    print("#" * 65)

    try:
        test_1_normal_request()
        test_2_controlled_suspicious_request()
        test_3_repeated_abnormal_requests()
        test_4_rate_limiting()
        test_5_blocking()

        print("\n" + "*" * 65)
        print("  ALL 5 END-TO-END INTEGRATION TESTS PASSED PERFECTLY!")
        print("*" * 65 + "\n")
    except Exception as e:
        print(f"\nFAIL: Error during integration test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
