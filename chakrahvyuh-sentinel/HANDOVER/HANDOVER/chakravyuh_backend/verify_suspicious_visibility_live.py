import httpx

def main():
    print("Starting live verification against Chakravyuh Sentinel on http://127.0.0.1:8000...")

    # 1. Test live GET with safe query param and secret password
    resp1 = httpx.get(
        "http://127.0.0.1:8000/stats?demo_param=safe_test_value&password=MyTopSecretPassword!",
        headers={"X-Forwarded-For": "192.0.2.111"}
    )
    print("1. GET /stats status:", resp1.status_code)
    assert resp1.status_code == 200

    # 2. Check /requests for query sanitization and redaction
    reqs = httpx.get("http://127.0.0.1:8000/requests?ip=192.0.2.111&source_site=all&limit=1").json()
    assert len(reqs) > 0, "No request log found for test IP"
    latest = reqs[0]
    print("2. Captured query_data:", latest.get("query_data"))
    assert "safe_test_value" in latest.get("query_data"), "Safe query param missing from log"
    assert "MyTopSecretPassword!" not in latest.get("query_data"), "Plaintext password leaked into log!"
    assert "[REDACTED]" in latest.get("query_data"), "Redaction token missing from log"
    print("   -> Verified: Safe param retained, sensitive password redacted!")

    # 3. Test SQLi attack block and evidence correlation
    sqli_url = "http://127.0.0.1:8000/services?q=' OR '1'='1 --"
    resp2 = httpx.get(sqli_url, headers={"X-Forwarded-For": "192.0.2.222"})
    print("3. SQLi Attack status:", resp2.status_code, "(Expected 403)")
    assert resp2.status_code == 403
    assert resp2.json().get("action") == "BLOCK"

    # 4. Check /blocked-ips for triggering request
    blocks = httpx.get("http://127.0.0.1:8000/blocked-ips?active_only=true").json()
    block_record = next((b for b in blocks if b["ip"] == "192.0.2.222"), None)
    assert block_record is not None, "Blocked record not found in active blocks"
    print("4. Blocked record found for IP:", block_record["ip"])
    tr = block_record.get("triggering_request")
    print("   Triggering request details:", tr)
    assert tr is not None, "Triggering request was not correlated"
    assert tr["status_code"] == 403, f"Expected 403 status code, got {tr['status_code']}"
    assert "OR '1'='1" in tr["query_data"], "SQLi evidence missing from triggering request"
    print("   -> Verified: Triggering request and SQLi evidence successfully correlated with block!")

    # 5. Check dedicated evidence endpoint
    ev_resp = httpx.get(f"http://127.0.0.1:8000/blocked-ips/{block_record['id']}/evidence")
    assert ev_resp.status_code == 200
    assert ev_resp.json().get("triggering_request") is not None
    print("5. Dedicated evidence endpoint verified: HTTP 200 OK")

    # 6. Test JSON POST request with safe field and sensitive token
    ingest_payload = {
        "ip": "192.0.2.333",
        "source_site": "x-beauty",
        "method": "POST",
        "endpoint": "/api/bookings/search",
        "status_code": 200,
        "timestamp": "2026-10-24T00:00:00Z",
        "query_data": '{"service": "pedicure", "safe_note": "window seat", "password": "SuperSecretPassword123"}',
    }
    resp3 = httpx.post("http://127.0.0.1:8000/api/ingest-traffic", json=ingest_payload)
    assert resp3.status_code == 200
    ingest_logs = httpx.get("http://127.0.0.1:8000/requests?ip=192.0.2.333&limit=1").json()
    assert len(ingest_logs) > 0
    ingest_entry = ingest_logs[0]
    print("6. Ingested JSON query_data:", ingest_entry.get("query_data"))
    assert "pedicure" in ingest_entry.get("query_data")
    assert "window seat" in ingest_entry.get("query_data")
    assert "SuperSecretPassword123" not in ingest_entry.get("query_data")
    assert "[REDACTED]" in ingest_entry.get("query_data")
    print("   -> Verified: Safe JSON fields captured, sensitive password redacted!")

    print("\nALL LIVE HTTP VERIFICATION CHECKS PASSED PERFECTLY!\n")

if __name__ == "__main__":
    main()
