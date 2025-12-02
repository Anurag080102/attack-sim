"""
Attack-Sim Flask Application Factory
"""

from flask import Flask
import logging


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

    # Configure logging
    _configure_logging(app)

    # Register error handlers
    from app.errors import register_error_handlers

    register_error_handlers(app)

    # Register blueprints
    from app.routes import register_blueprints

    register_blueprints(app)

    # Health check endpoint
    @app.route("/health")
    def health():
        return {"status": "healthy", "app": "attack-sim"}

    return app


def _configure_logging(app: Flask) -> None:
    """
    Configure logging for the application.

    Args:
        app: Flask application instance
    """
    log_level = logging.DEBUG if app.debug else logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Set Flask's logger level
    app.logger.setLevel(log_level)

    # Reduce noise from some libraries
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
