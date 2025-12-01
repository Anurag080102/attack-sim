"""
Attack-Sim Configuration Classes
"""
import os
from pathlib import Path


class Config:
    """Base configuration class."""
    
    # Base directory
    BASE_DIR = Path(__file__).resolve().parent.parent
    
    # Flask settings
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    
    # Application settings
    APP_NAME = "Attack-Sim"
    APP_VERSION = "0.1.0"
    
    # Reports directory
    REPORTS_DIR = BASE_DIR / "reports"
    
    # Wordlists directory
    WORDLISTS_DIR = BASE_DIR / "wordlists"
    
    # Attack settings
    DEFAULT_TIMEOUT = 10  # seconds
    DEFAULT_THREADS = 4
    MAX_THREADS = 20


class DevelopmentConfig(Config):
    """Development configuration."""
    
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing configuration."""
    
    DEBUG = False
    TESTING = True
    SECRET_KEY = "testing-secret-key"


class ProductionConfig(Config):
    """Production configuration."""
    
    DEBUG = False
    TESTING = False
    
    # Override SECRET_KEY in production via environment variable
    SECRET_KEY = os.environ.get("SECRET_KEY")
    
    def __init__(self):
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY environment variable must be set in production")


# Configuration dictionary for easy access
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
