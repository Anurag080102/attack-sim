"""
Attack-Sim Configuration Classes

This module provides configuration classes for different environments:
- DevelopmentConfig: For local development with debug enabled
- TestingConfig: For running unit tests
- ProductionConfig: For production deployment

Configuration values can be overridden via environment variables.
"""

import os
from pathlib import Path


class Config:
    """
    Base configuration class.

    Contains common settings shared across all environments.

    Attributes:
        BASE_DIR: Root directory of the application
        SECRET_KEY: Flask secret key for session management
        APP_NAME: Application name
        APP_VERSION: Current version string
        REPORTS_DIR: Directory for storing generated reports
        WORDLISTS_DIR: Directory containing wordlist files
        DEFAULT_TIMEOUT: Default HTTP request timeout in seconds
        DEFAULT_THREADS: Default number of worker threads
        MAX_THREADS: Maximum allowed worker threads
    """

    # Base directory (navigate from src/main/python/app/config.py to project root)
    BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

    # Flask settings
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

    # Application settings
    APP_NAME = "Attack-Sim"
    APP_VERSION = "0.1.0"

    # Reports directory (Maven-style: target/reports)
    REPORTS_DIR = BASE_DIR / "target" / "reports"

    # Wordlists directory (Maven-style: src/main/resources/wordlists)
    WORDLISTS_DIR = BASE_DIR / "src" / "main" / "resources" / "wordlists"

    # Attack settings
    DEFAULT_TIMEOUT = 10  # seconds
    DEFAULT_THREADS = 4
    MAX_THREADS = 20


class DevelopmentConfig(Config):
    """
    Development configuration.

    Enables debug mode for development with automatic reloading
    and detailed error messages.
    """

    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """
    Testing configuration.

    Used for running unit tests with a fixed secret key
    and testing-specific settings.
    """

    DEBUG = False
    TESTING = True
    SECRET_KEY = "testing-secret-key"


class ProductionConfig(Config):
    """
    Production configuration.

    Requires SECRET_KEY to be set via environment variable.
    Debug mode is disabled for security.

    Raises:
        ValueError: If SECRET_KEY environment variable is not set
    """

    DEBUG = False
    TESTING = False

    # Override SECRET_KEY in production via environment variable
    SECRET_KEY = os.environ.get("SECRET_KEY")

    def __init__(self):
        """Initialize production config with validation."""
        if not self.SECRET_KEY:
            raise ValueError(
                "SECRET_KEY environment variable must be set in production"
            )


# Configuration dictionary for easy access
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
