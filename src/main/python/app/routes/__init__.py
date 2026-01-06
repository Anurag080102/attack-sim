"""
Attack-Sim Routes Module

This module contains all Flask blueprints for the application.
It provides a function to register all blueprints with the Flask app.
"""

from flask import Flask


def register_blueprints(app: Flask) -> None:
    """
    Register all blueprints with the Flask application.

    Args:
        app: Flask application instance
    """
    from app.routes.attacks import attacks_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.reports import reports_bp

    # Register blueprints with appropriate URL prefixes
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(attacks_bp, url_prefix="/api")
    app.register_blueprint(reports_bp, url_prefix="/api")


__all__ = ["register_blueprints"]
