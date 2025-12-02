"""
Dashboard Routes

This module provides routes for the main dashboard and related pages.
"""

from flask import Blueprint, render_template, jsonify, current_app

from app.routes.attacks import attack_manager, AttackRegistry, OWASPRegistry


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """
    Render the main dashboard page.

    Returns:
        Rendered dashboard HTML template
    """
    return render_template("dashboard.html", active_page="dashboard")


@dashboard_bp.route("/reports")
def reports_page():
    """
    Render the reports page.

    Returns:
        Rendered reports HTML template
    """
    return render_template("reports.html", active_page="reports")


@dashboard_bp.route("/results/<job_id>")
def results_page(job_id: str):
    """
    Render the results page for a specific job.

    Args:
        job_id: ID of the attack job

    Returns:
        Rendered results HTML template
    """
    job = attack_manager.get_job(job_id)

    if job is None:
        return (
            render_template(
                "error.html",
                error="Job Not Found",
                message=f"The attack job '{job_id}' was not found.",
            ),
            404,
        )

    return render_template("results.html", job=job.to_dict(), active_page="dashboard")


@dashboard_bp.route("/attack/<attack_id>")
def attack_config_page(attack_id: str):
    """
    Render the attack configuration page.

    Args:
        attack_id: ID of the attack to configure

    Returns:
        Rendered attack configuration HTML template
    """
    # Try to get attack from main registry first, then OWASP registry
    attack = AttackRegistry.create(attack_id)
    if attack is None:
        attack = OWASPRegistry.create(attack_id)

    if attack is None:
        return (
            render_template(
                "error.html",
                error="Attack Not Found",
                message=f"The attack '{attack_id}' was not found.",
            ),
            404,
        )

    attack_info = attack.get_info()

    # Determine category
    if attack_id in [a["id"] for a in AttackRegistry.list_attacks()]:
        attack_info["category"] = "core"
    else:
        attack_info["category"] = "owasp"

    return render_template("attack_config.html", attack=attack_info, active_page="dashboard")


@dashboard_bp.route("/api/info")
def app_info():
    """
    Get application information.

    Returns:
        JSON with app name, version, and available features
    """
    return jsonify(
        {
            "name": current_app.config.get("APP_NAME", "Attack-Sim"),
            "version": current_app.config.get("APP_VERSION", "0.1.0"),
            "description": "Security Testing Tool for simulating common attack vectors",
            "features": [
                "Brute Force Attacks",
                "Dictionary Attacks",
                "OWASP Top 10 Vulnerability Scanning",
            ],
        }
    )
