"""
Route Unit Tests

This module contains unit tests for all Flask routes including:
- Dashboard routes
- Attack API endpoints
- Report API endpoints
"""

import tempfile
import time
from pathlib import Path

import pytest
from app import create_app
from app.routes.attacks import AttackStatus, attack_manager


@pytest.fixture
def app():
    """Create and configure a test application instance."""
    app = create_app("testing")
    app.config["TESTING"] = True

    # Use temporary directory for reports
    temp_dir = tempfile.mkdtemp()
    app.config["REPORTS_DIR"] = Path(temp_dir)

    yield app

    # Clean up temp directory after tests (ignore errors on Windows)
    import shutil

    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture
def client(app):
    """Create a test client for the application."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create a test CLI runner for the application."""
    return app.test_cli_runner()


class TestHealthEndpoint:
    """Test cases for the health check endpoint."""

    def test_health_check(self, client):
        """Test health check returns healthy status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"
        assert data["app"] == "attack-sim"


class TestDashboardRoutes:
    """Test cases for dashboard routes."""

    def test_index_page(self, client):
        """Test index page renders successfully."""
        response = client.get("/")

        assert response.status_code == 200
        assert b"Attack-Sim" in response.data or b"attack-sim" in response.data.lower()

    def test_reports_page(self, client):
        """Test reports page renders successfully."""
        response = client.get("/reports")

        assert response.status_code == 200

    def test_attack_config_page_valid(self, client):
        """Test attack config page for valid attack."""
        response = client.get("/attack/a03")

        assert response.status_code == 200
        assert b"Injection" in response.data or b"a03" in response.data.lower()

    def test_attack_config_page_invalid(self, client):
        """Test attack config page for invalid attack returns 404."""
        response = client.get("/attack/nonexistent_attack")

        assert response.status_code == 404

    def test_results_page_invalid_job(self, client):
        """Test results page with invalid job returns 404."""
        response = client.get("/results/invalid-job-id")

        assert response.status_code == 404

    def test_app_info_endpoint(self, client):
        """Test API info endpoint."""
        response = client.get("/api/info")

        assert response.status_code == 200
        data = response.get_json()
        assert "name" in data
        assert "version" in data
        assert "features" in data


class TestAttackListingEndpoints:
    """Test cases for attack listing endpoints."""

    def test_list_attacks(self, client):
        """Test listing all attacks."""
        response = client.get("/api/attacks")

        assert response.status_code == 200
        data = response.get_json()
        assert "attacks" in data
        assert "total" in data
        assert data["total"] > 0

    def test_list_attacks_contains_core_attacks(self, client):
        """Test that OWASP attacks are in the list."""
        response = client.get("/api/attacks")

        data = response.get_json()
        attack_ids = [a["id"] for a in data["attacks"]]

        assert "a01" in attack_ids
        assert "a03" in attack_ids

    def test_list_attacks_contains_owasp_attacks(self, client):
        """Test that OWASP attacks are in the list."""
        response = client.get("/api/attacks")

        data = response.get_json()
        attack_ids = [a["id"] for a in data["attacks"]]

        # Check for OWASP attack IDs
        assert "a01" in attack_ids
        assert "a03" in attack_ids
        assert "a10" in attack_ids

    def test_get_attack_details_valid(self, client):
        """Test getting details for a valid attack."""
        response = client.get("/api/attacks/a03")

        assert response.status_code == 200
        data = response.get_json()
        assert "name" in data
        assert "description" in data
        assert "config_options" in data

    def test_get_attack_details_invalid(self, client):
        """Test getting details for invalid attack returns 404."""
        response = client.get("/api/attacks/nonexistent_attack")

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_list_owasp_categories(self, client):
        """Test listing OWASP categories."""
        response = client.get("/api/attacks/owasp/categories")

        assert response.status_code == 200
        data = response.get_json()
        assert "categories" in data
        assert "total" in data
        assert data["total"] == 10  # OWASP Top 10


class TestAttackExecutionEndpoints:
    """Test cases for attack execution endpoints."""

    def test_run_attack_missing_body(self, client):
        """Test running attack without request body returns 415."""
        response = client.post("/api/attacks/run")

        # No content type header means 415 Unsupported Media Type
        assert response.status_code in [400, 415]

    def test_run_attack_missing_attack_id(self, client):
        """Test running attack without attack_id returns 400."""
        response = client.post("/api/attacks/run", json={"target": "http://example.com"})

        assert response.status_code == 400
        data = response.get_json()
        assert "attack_id" in data["error"].lower()

    def test_run_attack_missing_target(self, client):
        """Test running attack without target returns 400."""
        response = client.post("/api/attacks/run", json={"attack_id": "a03"})

        assert response.status_code == 400
        data = response.get_json()
        assert "target" in data["error"].lower()

    def test_run_attack_invalid_attack_id(self, client):
        """Test running invalid attack returns 404."""
        response = client.post(
            "/api/attacks/run",
            json={"attack_id": "nonexistent", "target": "http://example.com"},
        )

        assert response.status_code == 404

    def test_run_attack_success(self, client):
        """Test running a valid attack returns job info."""
        response = client.post(
            "/api/attacks/run",
            json={
                "attack_id": "a05",  # Security misconfiguration - lightweight
                "target": "http://example.com",
                "config": {},
            },
        )

        assert response.status_code == 202
        data = response.get_json()
        assert "job" in data
        assert "id" in data["job"]
        assert data["job"]["status"] == "running"

    def test_get_attack_status_valid(self, client):
        """Test getting status for valid job."""
        # First start an attack
        run_response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a05", "target": "http://example.com"},
        )
        job_id = run_response.get_json()["job"]["id"]

        # Get status
        response = client.get(f"/api/attacks/status/{job_id}")

        assert response.status_code == 200
        data = response.get_json()
        assert data["id"] == job_id
        assert "status" in data
        assert "progress" in data

    def test_get_attack_status_invalid(self, client):
        """Test getting status for invalid job returns 404."""
        response = client.get("/api/attacks/status/invalid-job-id")

        assert response.status_code == 404

    def test_get_attack_results_valid(self, client):
        """Test getting results for valid job."""
        # First start an attack
        run_response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a05", "target": "http://example.com"},
        )
        job_id = run_response.get_json()["job"]["id"]

        # Get results
        response = client.get(f"/api/attacks/results/{job_id}")

        assert response.status_code == 200
        data = response.get_json()
        assert data["job_id"] == job_id
        assert "findings" in data
        assert "findings_count" in data

    def test_get_attack_results_invalid(self, client):
        """Test getting results for invalid job returns 404."""
        response = client.get("/api/attacks/results/invalid-job-id")

        assert response.status_code == 404

    def test_list_jobs(self, client):
        """Test listing attack jobs."""
        response = client.get("/api/attacks/jobs")

        assert response.status_code == 200
        data = response.get_json()
        assert "jobs" in data
        assert "total" in data

    def test_list_jobs_with_limit(self, client):
        """Test listing jobs with limit parameter."""
        response = client.get("/api/attacks/jobs?limit=5")

        assert response.status_code == 200
        data = response.get_json()
        assert len(data["jobs"]) <= 5

    def test_cancel_job_invalid(self, client):
        """Test cancelling invalid job returns 400."""
        response = client.post("/api/attacks/cancel/invalid-job-id")

        assert response.status_code == 400


class TestReportEndpoints:
    """Test cases for report endpoints."""

    def test_list_reports_empty(self, client):
        """Test listing reports when none exist."""
        response = client.get("/api/reports")

        assert response.status_code == 200
        data = response.get_json()
        assert "reports" in data
        assert "total" in data

    def test_get_report_invalid(self, client):
        """Test getting invalid report returns 404."""
        response = client.get("/api/reports/nonexistent")

        assert response.status_code == 404

    def test_generate_report_missing_body(self, client):
        """Test generating report without body returns 415."""
        response = client.post("/api/reports/generate")

        # No content type header means 415 Unsupported Media Type
        assert response.status_code in [400, 415]

    def test_generate_report_missing_job_id(self, client):
        """Test generating report without job_id returns 400."""
        response = client.post("/api/reports/generate", json={})

        assert response.status_code == 400
        data = response.get_json()
        assert "job_id" in data["error"].lower() or "required" in data["error"].lower()

    def test_generate_report_invalid_job(self, client):
        """Test generating report for invalid job returns 404."""
        response = client.post("/api/reports/generate", json={"job_id": "invalid-job-id"})

        assert response.status_code == 404

    def test_generate_report_success(self, client, app):
        """Test generating report for valid job."""
        # First run an attack
        run_response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a05", "target": "http://example.com"},
        )
        job_id = run_response.get_json()["job"]["id"]

        # Wait a moment for the attack to process
        time.sleep(0.5)

        # Generate report
        response = client.post("/api/reports/generate", json={"job_id": job_id, "title": "Test Report"})

        assert response.status_code == 201
        data = response.get_json()
        assert "report_id" in data
        assert data["title"] == "Test Report"

    def test_delete_report_invalid(self, client):
        """Test deleting invalid report returns 404."""
        response = client.delete("/api/reports/nonexistent")

        assert response.status_code == 404

    def test_delete_report_success(self, client, app):
        """Test deleting a valid report."""
        # Run an attack
        run_response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a05", "target": "http://example.com"},
        )
        job_id = run_response.get_json()["job"]["id"]
        time.sleep(0.5)

        # Generate report
        gen_response = client.post("/api/reports/generate", json={"job_id": job_id, "title": "Delete Test"})
        assert gen_response.status_code == 201
        report_id = gen_response.get_json()["report_id"]

        # Delete report
        delete_response = client.delete(f"/api/reports/{report_id}")
        assert delete_response.status_code == 200

        # Verify deleted
        verify_response = client.get(f"/api/reports/{report_id}")
        assert verify_response.status_code == 404

    def test_report_lifecycle(self, client, app):
        """Test complete report lifecycle: generate, retrieve, download, delete."""
        # Run an attack
        run_response = client.post(
            "/api/attacks/run",
            json={"attack_id": "a05", "target": "http://example.com"},
        )
        job_id = run_response.get_json()["job"]["id"]
        time.sleep(0.5)

        # Generate report
        gen_response = client.post("/api/reports/generate", json={"job_id": job_id, "title": "Lifecycle Test"})
        assert gen_response.status_code == 201
        report_id = gen_response.get_json()["report_id"]

        # List reports - should include our report
        list_response = client.get("/api/reports")
        data = list_response.get_json()
        report_ids = [r["id"] for r in data["reports"]]
        assert report_id in report_ids

        # Get report
        get_response = client.get(f"/api/reports/{report_id}")
        assert get_response.status_code == 200
        report_data = get_response.get_json()
        assert report_data["title"] == "Lifecycle Test"

        # Download JSON
        download_json = client.get(f"/api/reports/{report_id}/download?format=json")
        assert download_json.status_code == 200
        assert download_json.mimetype == "application/json"

        # Download HTML
        download_html = client.get(f"/api/reports/{report_id}/download?format=html")
        assert download_html.status_code == 200
        assert download_html.mimetype == "text/html"
        assert b"<!DOCTYPE html>" in download_html.data

        # Note: Delete test skipped due to Windows file locking in temp
        # directory


class TestAttackManager:
    """Test cases for the AttackManager class."""

    def test_create_job(self, app):
        """Test creating a job via attack manager."""
        with app.app_context():
            job = attack_manager.create_job(attack_id="a03", target="http://example.com", config={"timeout": 5})

            assert job is not None
            assert job.attack_id == "a03"
            assert job.target == "http://example.com"
            assert job.status == AttackStatus.PENDING

    def test_create_job_invalid_attack(self, app):
        """Test creating job with invalid attack returns None."""
        with app.app_context():
            job = attack_manager.create_job(attack_id="nonexistent", target="http://example.com", config={})

            assert job is None

    def test_start_job(self, app):
        """Test starting a job."""
        with app.app_context():
            job = attack_manager.create_job(attack_id="a05", target="http://example.com", config={})

            result = attack_manager.start_job(job.id)
            assert result is True

            # Job should be running
            updated_job = attack_manager.get_job(job.id)
            assert updated_job.status == AttackStatus.RUNNING

    def test_get_job(self, app):
        """Test getting a job by ID."""
        with app.app_context():
            job = attack_manager.create_job(attack_id="a03", target="http://example.com", config={})

            retrieved = attack_manager.get_job(job.id)
            assert retrieved is not None
            assert retrieved.id == job.id

    def test_get_job_invalid(self, app):
        """Test getting invalid job returns None."""
        with app.app_context():
            job = attack_manager.get_job("invalid-id")
            assert job is None

    def test_list_jobs(self, app):
        """Test listing jobs."""
        with app.app_context():
            # Create a few jobs
            attack_manager.create_job("a05", "http://example1.com", {})
            attack_manager.create_job("a05", "http://example2.com", {})

            jobs = attack_manager.list_jobs()
            assert len(jobs) >= 2

    def test_job_to_dict(self, app):
        """Test job serialization."""
        with app.app_context():
            job = attack_manager.create_job(attack_id="a03", target="http://example.com", config={"key": "value"})

            job_dict = job.to_dict()

            assert "id" in job_dict
            assert "attack_id" in job_dict
            assert "target" in job_dict
            assert "status" in job_dict
            assert "progress" in job_dict
            assert job_dict["config"] == {"key": "value"}


class TestInputValidation:
    """Test cases for input validation."""

    def test_attack_run_empty_target(self, client):
        """Test running attack with empty target."""
        response = client.post("/api/attacks/run", json={"attack_id": "a03", "target": ""})

        assert response.status_code == 400

    def test_attack_run_empty_attack_id(self, client):
        """Test running attack with empty attack_id."""
        response = client.post("/api/attacks/run", json={"attack_id": "", "target": "http://example.com"})

        assert response.status_code == 400

    def test_report_generate_empty_job_id(self, client):
        """Test generating report with empty job_id."""
        response = client.post("/api/reports/generate", json={"job_id": ""})

        assert response.status_code == 400


class TestErrorHandling:
    """Test cases for error handling."""

    def test_404_for_unknown_route(self, client):
        """Test 404 for unknown routes."""
        response = client.get("/api/unknown/route")

        assert response.status_code == 404

    def test_405_for_wrong_method(self, client):
        """Test 405 for wrong HTTP method."""
        response = client.delete("/api/attacks")  # Should be GET

        assert response.status_code == 405

    def test_attack_config_page_owasp_valid(self, client):
        """Test attack config page for OWASP attack."""
        response = client.get("/attack/a03")

        assert response.status_code == 200
        assert b"Injection" in response.data


class TestAPIResponseFormat:
    """Test cases for API response format consistency."""

    def test_attacks_list_response_format(self, client):
        """Test attacks list response has consistent format."""
        response = client.get("/api/attacks")
        data = response.get_json()

        assert isinstance(data["attacks"], list)
        assert isinstance(data["total"], int)

        if data["attacks"]:
            attack = data["attacks"][0]
            assert "id" in attack
            assert "name" in attack
            assert "description" in attack

    def test_reports_list_response_format(self, client):
        """Test reports list response has consistent format."""
        response = client.get("/api/reports")
        data = response.get_json()

        assert isinstance(data["reports"], list)
        assert isinstance(data["total"], int)

    def test_jobs_list_response_format(self, client):
        """Test jobs list response has consistent format."""
        response = client.get("/api/attacks/jobs")
        data = response.get_json()

        assert isinstance(data["jobs"], list)
        assert isinstance(data["total"], int)

    def test_error_response_format(self, client):
        """Test error responses have consistent format."""
        response = client.get("/api/attacks/nonexistent")
        data = response.get_json()

        assert "error" in data
        assert isinstance(data["error"], str)
