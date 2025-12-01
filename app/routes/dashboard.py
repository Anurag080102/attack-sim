"""
Dashboard Routes

This module provides routes for the main dashboard and index page.
"""

from flask import Blueprint, render_template, jsonify, current_app


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """
    Render the main dashboard page.
    
    Returns:
        Rendered dashboard HTML template
    """
    return render_template("dashboard.html")


@dashboard_bp.route("/api/info")
def app_info():
    """
    Get application information.
    
    Returns:
        JSON with app name, version, and available features
    """
    return jsonify({
        "name": current_app.config.get("APP_NAME", "Attack-Sim"),
        "version": current_app.config.get("APP_VERSION", "0.1.0"),
        "description": "Security Testing Tool for simulating common attack vectors",
        "features": [
            "Brute Force Attacks",
            "Dictionary Attacks",
            "OWASP Top 10 Vulnerability Scanning"
        ]
    })
