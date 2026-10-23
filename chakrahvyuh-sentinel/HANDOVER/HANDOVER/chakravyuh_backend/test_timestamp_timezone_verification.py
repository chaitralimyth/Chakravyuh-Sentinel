"""
Timestamp & Timezone Verification Suite for Chakravyuh-Sentinel.

Verifies:
1. Backend _iso serialization attaches UTC 'Z' suffix to naive and UTC datetimes.
2. Backend /requests endpoint returns UTC-aware ISO-8601 strings.
3. JavaScript format.js parser and formatter (via Node):
   - Correctly converts UTC timestamps to Asia/Kolkata (IST).
   - Known sample: '2026-10-23T18:23:36.665174Z' -> '23 Oct 2026, 11:53:36 PM'.
   - Naive sample: '2026-10-23T18:23:36.665174' -> '23 Oct 2026, 11:53:36 PM'.
4. Real request to X-Beauty produces a current timestamp within reasonable processing delay.
"""

import os
import sys
import json
import subprocess
from datetime import datetime, timezone
import urllib.request

# Ensure app imports work
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from app.dashboard_routes import _iso


def test_1_backend_iso_serialization():
    print("\n--- Test 1: Backend _iso Serialization ---")
    # Naive datetime (representing UTC in SQLite)
    naive_dt = datetime(2026, 10, 23, 18, 23, 36, 665174)
    iso_naive = _iso(naive_dt)
    assert iso_naive == "2026-10-23T18:23:36.665174Z", f"Expected Z suffix, got {iso_naive}"
    print(f"[PASS] Naive datetime serialized as: {iso_naive}")

    # UTC-aware datetime
    utc_dt = datetime(2026, 10, 23, 18, 23, 36, 665174, tzinfo=timezone.utc)
    iso_utc = _iso(utc_dt)
    assert iso_utc == "2026-10-23T18:23:36.665174Z", f"Expected Z suffix, got {iso_utc}"
    print(f"[PASS] UTC-aware datetime serialized as: {iso_utc}")


def test_2_requests_endpoint_utc_timestamps():
    print("\n--- Test 2: Live /requests Endpoint UTC Timestamps ---")
    url = "http://127.0.0.1:8000/requests?limit=10"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        logs = json.loads(resp.read().decode("utf-8"))
        assert len(logs) > 0, "Expected at least 1 log entry"
        latest = logs[0]
        ts = latest["timestamp"]
        assert ts.endswith("Z"), f"Expected timestamp to end with 'Z', got: {ts}"
        print(f"[PASS] Latest record id={latest['id']} timestamp: {ts}")


def test_3_node_ist_display_conversion():
    print("\n--- Test 3: Frontend format.js IST (Asia/Kolkata) Conversion ---")
    js_file = os.path.abspath(
        os.path.join(
            CURRENT_DIR,
            "../../../sentinel_security_dashboard/stitch_sentinel_security_dashboard/js/format.js",
        )
    )
    assert os.path.exists(js_file), f"format.js not found at {js_file}"

    node_script = f"""
    const fs = require('fs');
    const code = fs.readFileSync({json.dumps(js_file)}, 'utf8');
    const window = {{}};
    eval(code);
    const F = window.SentinelFormat;

    const testUtc = '2026-10-23T18:23:36.665174Z';
    const testNaive = '2026-10-23T18:23:36.665174';

    const outUtc = F.datetime(testUtc);
    const outNaive = F.datetime(testNaive);

    console.log(JSON.stringify({{
      outUtc,
      outNaive,
      expected: '23 Oct 2026, 11:53:36 PM'
    }}));
    """

    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)
    print(f"[PASS] Formatted UTC:   {data['outUtc']}")
    print(f"[PASS] Formatted Naive: {data['outNaive']}")
    assert data["outUtc"] == data["expected"], f"Expected {data['expected']}, got {data['outUtc']}"
    assert data["outNaive"] == data["expected"], f"Expected {data['expected']}, got {data['outNaive']}"
    print("[PASS] Output matches expected Indian Standard Time display exactly!")


def test_4_real_request_flow_and_timestamp_accuracy():
    print("\n--- Test 4: Real Request Flow and Timestamp Accuracy ---")
    start_utc = datetime.now(timezone.utc)

    # Dispatch request to X-Beauty
    xbeauty_url = "http://127.0.0.1:8001/api/services?category=Hair"
    with urllib.request.urlopen(xbeauty_url) as resp:
        assert resp.status == 200

    # Wait briefly for asynchronous telemetry background task to commit to DB
    import time
    time.sleep(0.5)

    # Query Sentinel /requests
    sentinel_url = "http://127.0.0.1:8000/requests?limit=1"
    with urllib.request.urlopen(sentinel_url) as resp:
        logs = json.loads(resp.read().decode("utf-8"))
        latest = logs[0]
        ts_str = latest["timestamp"]
        assert ts_str.endswith("Z"), f"Expected Z suffix, got {ts_str}"
        record_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

        diff_seconds = abs((record_dt - start_utc).total_seconds())
        print(f"[PASS] New request record id={latest['id']}, endpoint={latest['endpoint']}, timestamp={ts_str}")
        print(f"[PASS] Difference between client dispatch and logged timestamp: {diff_seconds:.2f} seconds")
        assert diff_seconds < 10.0, f"Timestamp difference too large: {diff_seconds}s"


if __name__ == "__main__":
    test_1_backend_iso_serialization()
    test_2_requests_endpoint_utc_timestamps()
    test_3_node_ist_display_conversion()
    test_4_real_request_flow_and_timestamp_accuracy()
    print("\n=======================================================")
    print("  ALL TIMESTAMP AND TIMEZONE TESTS PASSED SUCCESSFULLY! ")
    print("=======================================================\n")
