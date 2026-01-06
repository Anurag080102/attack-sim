#!/usr/bin/env python3
"""
API Endpoint Test Script

Tests all API endpoints to verify Phase 5 implementation.
"""

import time

import requests

BASE_URL = "http://127.0.0.1:5000"


def test_endpoint(method, endpoint, data=None, expected_status=200):
    """Test an endpoint and print results."""
    url = f"{BASE_URL}{endpoint}"
    try:
        if method == "GET":
            r = requests.get(url, timeout=5)
        elif method == "POST":
            r = requests.post(url, json=data, timeout=5)
        elif method == "DELETE":
            r = requests.delete(url, timeout=5)
        else:
            print(f"Unknown method: {method}")
            return None

        status = "PASS" if r.status_code == expected_status else "FAIL"
        print(f"[{status}] {method} {endpoint} -> {r.status_code}")

        if r.status_code == expected_status:
            return r.json() if r.content else None
        else:
            print(f"       Response: {r.text[:200]}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"[FAIL] {method} {endpoint} -> Connection refused")
        return None
    except Exception as e:
        print(f"[FAIL] {method} {endpoint} -> {e}")
        return None


def main():
    print("=" * 60)
    print("Attack-Sim API Endpoint Tests")
    print("=" * 60)
    print()

    # Test dashboard endpoints
    print("--- Dashboard Endpoints ---")
    test_endpoint("GET", "/api/info")
    test_endpoint("GET", "/health")
    print()

    # Test attack listing endpoints
    print("--- Attack Listing Endpoints ---")
    attacks = test_endpoint("GET", "/api/attacks")
    if attacks:
        print(f"       Total attacks: {attacks.get('total', 0)}")

    test_endpoint("GET", "/api/attacks/a03")  # Injection
    test_endpoint("GET", "/api/attacks/a01")  # Broken Access Control
    test_endpoint("GET", "/api/attacks/nonexistent", expected_status=404)

    test_endpoint("GET", "/api/attacks/owasp/categories")
    print()

    # Test attack execution
    print("--- Attack Execution Endpoints ---")

    # Test missing parameters
    test_endpoint("POST", "/api/attacks/run", data={}, expected_status=400)
    test_endpoint(
        "POST", "/api/attacks/run", data={"attack_id": "a03"}, expected_status=400
    )

    # Test running an attack (will fail since no real target, but tests the
    # flow)
    job_result = test_endpoint(
        "POST",
        "/api/attacks/run",
        data={
            "attack_id": "a05",  # Security misconfiguration - doesn't require valid target
            "target": "http://example.com",
            "config": {},
        },
        expected_status=202,
    )

    if job_result:
        job_id = job_result.get("job", {}).get("id")
        print(f"       Job ID: {job_id}")

        if job_id:
            # Test status endpoint
            time.sleep(0.5)  # Let it start
            test_endpoint("GET", f"/api/attacks/status/{job_id}")

            # Test results endpoint
            test_endpoint("GET", f"/api/attacks/results/{job_id}")

    # Test jobs listing
    test_endpoint("GET", "/api/attacks/jobs")
    print()

    # Test report endpoints
    print("--- Report Endpoints ---")
    test_endpoint("GET", "/api/reports")
    test_endpoint("GET", "/api/reports/nonexistent", expected_status=404)

    # Generate a report if we have a job
    if job_result:
        job_id = job_result.get("job", {}).get("id")
        if job_id:
            time.sleep(2)  # Wait for job to complete
            report_result = test_endpoint(
                "POST",
                "/api/reports/generate",
                data={"job_id": job_id, "title": "Test Report"},
                expected_status=201,
            )

            if report_result:
                report_id = report_result.get("report_id")
                print(f"       Report ID: {report_id}")

                if report_id:
                    test_endpoint("GET", f"/api/reports/{report_id}")
                    test_endpoint("GET", "/api/reports")

    print()
    print("=" * 60)
    print("Tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
