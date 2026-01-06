"""
Pytest Configuration and Fixtures

This module provides shared fixtures for all test modules.
"""

import shutil
import tempfile
from pathlib import Path

import pytest
from app import create_app
from app.routes.attacks import attack_manager


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


@pytest.fixture
def temp_reports_dir(app):
    """
    Create a temporary reports directory.

    Returns the path to the temporary directory.
    """
    temp_dir = Path(tempfile.mkdtemp())
    app.config["REPORTS_DIR"] = temp_dir

    yield temp_dir

    # Cleanup
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_attack_manager():
    """Reset attack manager state before each test."""
    # Clear jobs before each test
    attack_manager._jobs.clear()
    yield
    # Clear jobs after each test
    attack_manager._jobs.clear()
