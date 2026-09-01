"""Smoke tests for dashboard read-only API endpoints."""

import os
import sys

# Allow running from repo root or backend directory
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from fastapi.testclient import TestClient


def main():
    from app.main import app

    client = TestClient(app)
    endpoints = [
        ("GET", "/"),
        ("GET", "/stats"),
        ("GET", "/statistics"),
        ("GET", "/alerts"),
        ("GET", "/blocked-ips"),
        ("GET", "/requests"),
        ("GET", "/sessions"),
    ]

    failed = 0
    for method, path in endpoints:
        response = client.request(method, path)
        ok = response.status_code == 200
        status = "OK" if ok else "FAIL"
        print(f"{status}  {method} {path} -> {response.status_code}")
        if not ok:
            failed += 1
            print(f"      {response.text[:200]}")
        elif path != "/":
            data = response.json()
            kind = "list" if isinstance(data, list) else "object"
            print(f"      response type: {kind}")

    if failed:
        sys.exit(1)
    print("\nAll dashboard endpoints responded with 200.")


if __name__ == "__main__":
    main()
