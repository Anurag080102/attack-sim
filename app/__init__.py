"""
Attack-Sim Flask Application Factory
"""
from flask import Flask


def create_app(config_name: str = "development") -> Flask:
    """
    Application factory for creating Flask app instances.
    
    Args:
        config_name: Configuration to use ('development', 'testing', 'production')
    
    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Load configuration
    from app.config import config
    app.config.from_object(config[config_name])
    
    # Register a simple hello world route for testing
    @app.route("/")
    def index():
        return "Hello World! Attack-Sim is running."
    
    @app.route("/health")
    def health():
        return {"status": "healthy", "app": "attack-sim"}
    
    return app
