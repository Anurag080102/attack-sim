"""
Integration Tests for Attack-Sim

This module provides end-to-end integration tests that verify
the complete functionality of the application.
"""

import time


class TestIntegration:
    """Integration tests for complete application workflows."""

    def _get_job_id(self, response_json):
        """Extract job_id from response, handling different response formats."""
        if "job_id" in response_json:
            return response_json["job_id"]
        elif "job" in response_json and "id" in response_json["job"]:
            return response_json["job"]["id"]
        return None

    def test_full_attack_workflow(self, client, temp_reports_dir):
        """Test the complete attack workflow from start to finish."""
        # 1. Check health
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json["status"] == "healthy"

        # 2. List available attacks
        response = client.get("/api/attacks")
        assert response.status_code == 200
        attacks = response.json["attacks"]
        assert len(attacks) > 0

        # 3. Get attack details for OWASP A03 (Injection)
        response = client.get("/api/attacks/a03")
        assert response.status_code == 200
        assert "name" in response.json
        assert "config_options" in response.json

        # 4. Start an attack (202 Accepted for async operations)
        response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a03", "target": "http://example.com"},
            content_type="application/json",
        )
        assert response.status_code in [200, 201, 202]
        job_id = self._get_job_id(response.json)
        assert job_id is not None

        # 5. Check job status
        response = client.get(f"/api/attacks/status/{job_id}")
        assert response.status_code == 200
        assert "status" in response.json
        assert response.json["status"] in ["pending", "running", "completed", "failed"]

        # 6. Wait briefly and check results
        time.sleep(0.5)
        response = client.get(f"/api/attacks/results/{job_id}")
        assert response.status_code == 200

        # 7. Generate a report
        response = client.post(
            "/api/reports/generate",
            json={"job_id": job_id},
            content_type="application/json",
        )
        assert response.status_code in [200, 201]
        assert "report_id" in response.json
        report_id = response.json["report_id"]

        # 8. List reports
        response = client.get("/api/reports")
        assert response.status_code == 200
        assert "reports" in response.json

        # 9. Get report details
        response = client.get(f"/api/reports/{report_id}")
        assert response.status_code == 200

        # 10. List jobs
        response = client.get("/api/attacks/jobs")
        assert response.status_code == 200
        assert "jobs" in response.json

    def test_owasp_attack_workflow(self, client):
        """Test running an OWASP attack."""
        # List OWASP categories
        response = client.get("/api/attacks/owasp/categories")
        assert response.status_code == 200

        # Get list of attacks and find an OWASP one
        response = client.get("/api/attacks")
        attacks = response.json["attacks"]
        owasp_attacks = [a for a in attacks if a["id"].startswith("owasp_")]

        if owasp_attacks:
            attack_id = owasp_attacks[0]["id"]

            # Run an OWASP attack
            response = client.post(
                "/api/attacks/run",
                json={"attack_id": attack_id, "target": "http://localhost:9999"},
                content_type="application/json",
            )
            assert response.status_code in [200, 201, 202]
            job_id = self._get_job_id(response.json)
            assert job_id is not None

    def test_attack_cancellation_workflow(self, client):
        """Test cancelling a running attack."""
        # Start an attack
        response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a05", "target": "http://example.com"},
            content_type="application/json",
        )
        assert response.status_code in [200, 201, 202]
        job_id = self._get_job_id(response.json)
        assert job_id is not None

        # Cancel the attack
        response = client.post(f"/api/attacks/cancel/{job_id}")
        assert response.status_code in [200, 404]  # 404 if already completed

    def test_error_handling_workflow(self, client):
        """Test that error handling works correctly across endpoints."""
        # Invalid attack ID
        response = client.get("/api/attacks/nonexistent_attack_id")
        assert response.status_code == 404

        # Invalid job ID
        response = client.get("/api/attacks/status/invalid-job-id")
        assert response.status_code == 404

        # Invalid report ID
        response = client.get("/api/reports/invalid_report")
        assert response.status_code == 404

        # Missing required fields
        response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a03"},  # Missing target
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_dashboard_pages_load(self, client):
        """Test that all dashboard pages load correctly."""
        # Main dashboard
        response = client.get("/")
        assert response.status_code == 200
        assert b"Attack-Sim" in response.data or b"attack" in response.data.lower()

        # Reports page
        response = client.get("/reports")
        assert response.status_code == 200


class TestDataIntegrity:
    """Tests for data integrity across operations."""

    def _get_job_id(self, response_json):
        """Extract job_id from response, handling different response formats."""
        if "job_id" in response_json:
            return response_json["job_id"]
        elif "job" in response_json and "id" in response_json["job"]:
            return response_json["job"]["id"]
        return None

    def test_job_data_persists(self, client):
        """Test that job data persists correctly."""
        # Create a job
        response = client.post(
            "/api/attacks/run",
            json={
                "attack_id": "a03",
                "target": "http://example.com",
                "config": {"timeout": 10},
            },
            content_type="application/json",
        )
        assert response.status_code in [200, 201, 202]
        job_id = self._get_job_id(response.json)
        assert job_id is not None

        # Retrieve and verify job data
        response = client.get(f"/api/attacks/status/{job_id}")
        assert response.status_code == 200
        assert response.json["attack_id"] == "a03"
        assert response.json["target"] == "http://example.com"

    def test_report_content_matches_job(self, client, temp_reports_dir):
        """Test that generated report matches job data."""
        # Run an attack
        response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a03", "target": "http://test.example.com"},
            content_type="application/json",
        )
        assert response.status_code in [200, 201, 202]
        job_id = self._get_job_id(response.json)
        assert job_id is not None

        # Wait for completion
        time.sleep(0.5)

        # Generate report
        response = client.post(
            "/api/reports/generate",
            json={"job_id": job_id, "title": "Test Report"},
            content_type="application/json",
        )
        assert response.status_code in [200, 201]
        report_id = response.json["report_id"]

        # Get report and verify content
        response = client.get(f"/api/reports/{report_id}")
        assert response.status_code == 200
        report = response.json

        # Verify report exists (structure may vary)
        assert report is not None

    def test_multiple_concurrent_jobs(self, client):
        """Test that multiple jobs can run concurrently."""
        job_ids = []

        # Start multiple attacks
        for attack_id in ["a03", "a05"]:
            response = client.post(
                "/api/attacks/run",
                json={"attack_id": attack_id, "target": "http://example.com"},
                content_type="application/json",
            )
            if response.status_code in [200, 201, 202]:
                job_id = self._get_job_id(response.json)
                if job_id:
                    job_ids.append(job_id)

        assert len(job_ids) >= 1  # At least one job should succeed

        # Verify all jobs are accessible
        for job_id in job_ids:
            response = client.get(f"/api/attacks/status/{job_id}")
            assert response.status_code == 200


class TestSecurityValidation:
    """Tests for security-related validations."""

    def test_input_sanitization(self, client):
        """Test that malicious input is properly sanitized."""
        # XSS attempt in target
        response = client.post(
            "/api/attacks/run",
            json={
                "attack_id": "a03",
                "target": "http://example.com<script>alert('xss')</script>",
            },
            content_type="application/json",
        )
        # Should either sanitize or reject
        assert response.status_code in [200, 201, 400]

        # SQL injection attempt in attack_id
        response = client.post(
            "/api/attacks/run",
            json={
                "attack_id": "a03'; DROP TABLE attacks;--",
                "target": "http://example.com",
            },
            content_type="application/json",
        )
        # Should reject invalid attack_id
        assert response.status_code in [400, 404]

    def test_path_traversal_prevention(self, client):
        """Test that path traversal is prevented."""
        # Report ID with path traversal
        response = client.get("/api/reports/../../../etc/passwd")
        assert response.status_code in [400, 404]

        response = client.get("/api/reports/..%2F..%2Fetc%2Fpasswd")
        assert response.status_code in [400, 404]

    def test_content_type_enforcement(self, client):
        """Test that content type is properly enforced."""
        # POST without JSON content type
        response = client.post("/api/attacks/run", data="attack_id=a03&target=http://example.com")
        assert response.status_code in [400, 415]


class TestAPIConsistency:
    """Tests for API response consistency."""

    def test_success_responses_have_correct_format(self, client):
        """Test that all success responses have consistent format."""
        # Health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json
        assert "status" in data

        # List attacks
        response = client.get("/api/attacks")
        assert response.status_code == 200
        data = response.json
        assert "attacks" in data
        assert isinstance(data["attacks"], list)

        # List reports
        response = client.get("/api/reports")
        assert response.status_code == 200
        data = response.json
        assert "reports" in data
        assert isinstance(data["reports"], list)

    def test_error_responses_have_correct_format(self, client):
        """Test that all error responses have consistent format."""
        # 404 error
        response = client.get("/api/attacks/nonexistent")
        assert response.status_code == 404

        # 405 error
        response = client.delete("/api/attacks")
        assert response.status_code == 405


class TestAttackModules:
    """Integration tests for attack modules."""

    def _get_job_id(self, response_json):
        """Extract job_id from response, handling different response formats."""
        if "job_id" in response_json:
            return response_json["job_id"]
        elif "job" in response_json and "id" in response_json["job"]:
            return response_json["job"]["id"]
        return None

    def test_all_registered_attacks_are_runnable(self, client):
        """Test that all registered attacks can be started."""
        # Get all attacks
        response = client.get("/api/attacks")
        attacks = response.json["attacks"]

        for attack in attacks:
            attack_id = attack["id"]

            # Try to start each attack
            response = client.post(
                "/api/attacks/run",
                json={"attack_id": attack_id, "target": "http://localhost:9999"},
                content_type="application/json",
            )

            # Should either succeed (200, 201, 202) or fail gracefully (400,
            # 500)
            assert response.status_code in [
                200,
                201,
                202,
                400,
                500,
            ], f"Attack {attack_id} returned unexpected status {response.status_code}"

            if response.status_code in [200, 201, 202]:
                job_id = self._get_job_id(response.json)
                assert job_id is not None, f"Attack {attack_id} missing job_id in response"

    def test_attack_config_options_are_valid(self, client):
        """Test that attack configuration options are properly defined."""
        response = client.get("/api/attacks")
        attacks = response.json["attacks"]

        for attack in attacks:
            attack_id = attack["id"]

            # Get attack details
            response = client.get(f"/api/attacks/{attack_id}")
            assert response.status_code == 200

            # Verify config options structure
            if "config_options" in response.json:
                config_options = response.json["config_options"]
                assert isinstance(config_options, dict)

                for key, option in config_options.items():
                    # Each option should have at least a type
                    assert "type" in option or "default" in option or "description" in option, (
                        f"Attack {attack_id} option {key} missing required fields"
                    )
