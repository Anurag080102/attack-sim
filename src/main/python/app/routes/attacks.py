"""
Attack Routes

This module provides API endpoints for attack execution, status tracking,
and results retrieval. Attacks run in background threads.
"""

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

# Ensure attacks are registered by importing the modules
import attacks.owasp.a01_broken_access  # noqa: F401
import attacks.owasp.a02_crypto_failures  # noqa: F401
import attacks.owasp.a03_injection  # noqa: F401
import attacks.owasp.a04_insecure_design  # noqa: F401
import attacks.owasp.a05_security_misconfig  # noqa: F401
import attacks.owasp.a06_outdated_components  # noqa: F401
import attacks.owasp.a07_auth_failures  # noqa: F401
import attacks.owasp.a08_integrity_failures  # noqa: F401
import attacks.owasp.a09_logging_monitoring  # noqa: F401
import attacks.owasp.a10_ssrf  # noqa: F401

# Import attack registries
from attacks import AttackRegistry
from attacks.base import BaseAttack
from attacks.owasp import OWASPRegistry
from flask import Blueprint, jsonify, request

# Import error handling
from app.errors import ValidationError

# Import validation utilities
from app.validation import (
    validate_attack_config,
    validate_integer,
    validate_required,
    validate_string,
    validate_url,
)

attacks_bp = Blueprint("attacks", __name__)


class AttackStatus(Enum):
    """Status of an attack execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AttackJob:
    """Represents an attack job execution."""

    id: str
    attack_id: str
    attack_name: str
    target: str
    config: Dict[str, Any]
    status: AttackStatus = AttackStatus.PENDING
    progress: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "target": self.target,
            "config": self.config,
            "status": self.status.value,
            "progress": self.progress,
            "findings_count": len(self.findings),
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class AttackManager:
    """
    Manages attack job execution and tracking.

    Handles background thread execution and maintains job state.
    """

    def __init__(self):
        self._jobs: Dict[str, AttackJob] = {}
        self._attacks: Dict[str, BaseAttack] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def create_job(self, attack_id: str, target: str, config: Dict[str, Any]) -> Optional[AttackJob]:
        """
        Create a new attack job.

        Args:
            attack_id: ID of the attack to run
            target: Target URL/IP
            config: Attack configuration parameters

        Returns:
            AttackJob if created successfully, None otherwise
        """
        # Try to get attack from main registry first, then OWASP registry
        attack = AttackRegistry.create(attack_id, **config)
        if attack is None:
            attack = OWASPRegistry.create(attack_id, **config)

        if attack is None:
            return None

        job_id = str(uuid.uuid4())
        job = AttackJob(
            id=job_id,
            attack_id=attack_id,
            attack_name=attack.name,
            target=target,
            config=config,
        )

        with self._lock:
            self._jobs[job_id] = job
            self._attacks[job_id] = attack

        return job

    def start_job(self, job_id: str) -> bool:
        """
        Start executing an attack job in a background thread.

        Args:
            job_id: ID of the job to start

        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            if job_id not in self._jobs:
                return False

            job = self._jobs[job_id]
            if job.status != AttackStatus.PENDING:
                return False

            job.status = AttackStatus.RUNNING
            job.started_at = datetime.now()

        thread = threading.Thread(target=self._run_attack, args=(job_id,), daemon=True)

        with self._lock:
            self._threads[job_id] = thread

        thread.start()
        return True

    def _run_attack(self, job_id: str) -> None:
        """
        Execute the attack in a background thread.

        Args:
            job_id: ID of the job to execute
        """
        with self._lock:
            job = self._jobs.get(job_id)
            attack = self._attacks.get(job_id)

        if not job or not attack:
            return

        try:
            # Run the attack and collect findings
            for finding in attack.run(job.target):
                with self._lock:
                    job.findings.append(finding.to_dict())
                    job.progress = attack.get_progress()

                    # Check if cancelled
                    if job.status == AttackStatus.CANCELLED:
                        break

            with self._lock:
                if job.status != AttackStatus.CANCELLED:
                    job.status = AttackStatus.COMPLETED
                job.progress = 100.0
                job.completed_at = datetime.now()

        except Exception as e:
            with self._lock:
                job.status = AttackStatus.FAILED
                job.error = str(e)
                job.completed_at = datetime.now()

    def get_job(self, job_id: str) -> Optional[AttackJob]:
        """Get a job by ID."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job_id in self._attacks:
                # Update progress from attack instance
                attack = self._attacks[job_id]
                job.progress = attack.get_progress()
            return job

    def get_job_findings(self, job_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get findings for a job."""
        with self._lock:
            job = self._jobs.get(job_id)
            return job.findings.copy() if job else None

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a running job.

        Args:
            job_id: ID of the job to cancel

        Returns:
            True if cancelled, False otherwise
        """
        with self._lock:
            job = self._jobs.get(job_id)
            attack = self._attacks.get(job_id)

            if not job or job.status != AttackStatus.RUNNING:
                return False

            job.status = AttackStatus.CANCELLED
            if attack:
                attack.cancel()

            return True

    def list_jobs(self, limit: int = 50) -> List[AttackJob]:
        """Get list of all jobs, most recent first."""
        with self._lock:
            jobs = list(self._jobs.values())

        # Sort by started_at (most recent first), None values at end
        jobs.sort(key=lambda j: j.started_at or datetime.min, reverse=True)

        return jobs[:limit]

    def cleanup_old_jobs(self, max_age_hours: int = 24) -> int:
        """Remove jobs older than specified age."""
        cutoff = datetime.now()
        removed = 0

        with self._lock:
            jobs_to_remove = []
            for job_id, job in self._jobs.items():
                if job.completed_at:
                    age = (cutoff - job.completed_at).total_seconds() / 3600
                    if age > max_age_hours:
                        jobs_to_remove.append(job_id)

            for job_id in jobs_to_remove:
                del self._jobs[job_id]
                self._attacks.pop(job_id, None)
                self._threads.pop(job_id, None)
                removed += 1

        return removed


# Global attack manager instance
attack_manager = AttackManager()


# API Endpoints


@attacks_bp.route("/attacks", methods=["GET"])
def list_attacks():
    """
    List all available attacks.

    Returns:
        JSON list of attack information
    """
    attack_list = []

    # Get attacks from main registry
    for attack_info in AttackRegistry.list_attacks():
        attack_info["category"] = "core"
        attack_list.append(attack_info)

    # Get attacks from OWASP registry
    for attack_info in OWASPRegistry.list_attacks():
        attack_info["category"] = "owasp"
        attack_list.append(attack_info)

    return jsonify({"attacks": attack_list, "total": len(attack_list)})


@attacks_bp.route("/attacks/<attack_id>", methods=["GET"])
def get_attack(attack_id: str):
    """
    Get information about a specific attack.

    Args:
        attack_id: ID of the attack

    Returns:
        JSON with attack details
    """
    attack = AttackRegistry.create(attack_id)
    if attack is None:
        attack = OWASPRegistry.create(attack_id)

    if attack is None:
        return jsonify({"error": f"Attack '{attack_id}' not found"}), 404

    attack_info = attack.get_info()

    # Convert config_options to parameters format for API consistency
    if "config_options" in attack_info:
        attack_info["parameters"] = {}
        for key, option in attack_info["config_options"].items():
            attack_info["parameters"][key] = {
                "name": option.get("name", key.replace("_", " ").title()),
                "type": option.get("type", "string"),
                "default": option.get("default"),
                "description": option.get("description", ""),
                "options": option.get("options"),
                "min": option.get("min"),
                "max": option.get("max"),
                "required": option.get("required", False),
                "placeholder": option.get("placeholder", ""),
            }

    return jsonify(attack_info)


@attacks_bp.route("/attacks/run", methods=["POST"])
def run_attack():
    """
    Execute an attack against a target.

    Request body:
        {
            "attack_id": "bruteforce",
            "target": "http://example.com",
            "config": {...}
        }

    Returns:
        JSON with job ID and status
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    # Validate required fields
    try:
        validate_required(data, ["attack_id", "target"])
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    attack_id = data.get("attack_id")
    target = data.get("target")
    config = data.get("config", {})

    # Debug: Log received config
    print(f"[DEBUG] Received attack config: {config}")

    # Validate attack_id format
    try:
        attack_id = validate_string(attack_id, "attack_id", min_length=1, max_length=50)
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    # Validate and normalize target URL
    try:
        target = validate_url(target, "target")
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    # Get attack to validate config
    attack = AttackRegistry.create(attack_id)
    if attack is None:
        attack = OWASPRegistry.create(attack_id)

    if attack is None:
        return jsonify({"error": f"Attack '{attack_id}' not found"}), 404

    # Validate configuration against attack's options
    try:
        config = validate_attack_config(config, attack.get_config_options())
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    # Create the job
    job = attack_manager.create_job(attack_id, target, config)

    if job is None:
        return jsonify({"error": "Failed to create attack job"}), 500

    # Start the job in background
    if not attack_manager.start_job(job.id):
        return jsonify({"error": "Failed to start attack"}), 500

    return jsonify({"message": "Attack started", "job": job.to_dict()}), 202


@attacks_bp.route("/attacks/status/<job_id>", methods=["GET"])
def get_attack_status(job_id: str):
    """
    Get the status of an attack job.

    Args:
        job_id: ID of the job

    Returns:
        JSON with job status
    """
    job = attack_manager.get_job(job_id)

    if job is None:
        return jsonify({"error": f"Job '{job_id}' not found"}), 404

    return jsonify(job.to_dict())


@attacks_bp.route("/attacks/results/<job_id>", methods=["GET"])
def get_attack_results(job_id: str):
    """
    Get the results/findings of an attack job.

    Args:
        job_id: ID of the job

    Returns:
        JSON with findings
    """
    job = attack_manager.get_job(job_id)

    if job is None:
        return jsonify({"error": f"Job '{job_id}' not found"}), 404

    findings = attack_manager.get_job_findings(job_id) or []

    return jsonify(
        {
            "job_id": job_id,
            "status": job.status.value,
            "progress": job.progress,
            "findings": findings,
            "findings_count": len(findings),
        }
    )


@attacks_bp.route("/attacks/cancel/<job_id>", methods=["POST"])
def cancel_attack(job_id: str):
    """
    Cancel a running attack job.

    Args:
        job_id: ID of the job to cancel

    Returns:
        JSON with cancellation status
    """
    if attack_manager.cancel_job(job_id):
        return jsonify({"message": f"Job '{job_id}' cancelled"})
    else:
        return jsonify({"error": f"Cannot cancel job '{job_id}'"}), 400


@attacks_bp.route("/attacks/jobs", methods=["GET"])
def list_jobs():
    """
    List all attack jobs.

    Query parameters:
        limit: Maximum number of jobs to return (default: 50, max: 500)

    Returns:
        JSON with list of jobs
    """
    try:
        limit = validate_integer(request.args.get("limit", 50), "limit", min_value=1, max_value=500)
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    jobs = attack_manager.list_jobs(limit)

    return jsonify({"jobs": [job.to_dict() for job in jobs], "total": len(jobs)})


@attacks_bp.route("/attacks/owasp/categories", methods=["GET"])
def list_owasp_categories():
    """
    List all OWASP attack categories.

    Returns:
        JSON with OWASP categories and their attacks
    """
    categories = OWASPRegistry.get_all_categories()
    return jsonify({"categories": categories, "total": len(categories)})


@attacks_bp.route("/attacks/run-all", methods=["POST"])
def run_all_attacks():
    """
    Run all OWASP attacks against a target.

    Request body:
        {
            "target": "http://example.com",
            "config": {...}
        }

    Returns:
        JSON with list of job IDs
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    # Validate required fields
    try:
        validate_required(data, ["target"])
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    target = data.get("target")
    config = data.get("config", {})

    # Validate and normalize target URL
    try:
        target = validate_url(target, "target")
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    # Get all OWASP attack IDs
    attack_ids = OWASPRegistry.get_attack_ids()

    if not attack_ids:
        return jsonify({"error": "No OWASP attacks available"}), 404

    # Create and start jobs for all attacks
    jobs = []
    for attack_id in attack_ids:
        job = attack_manager.create_job(attack_id, target, config)
        if job:
            if attack_manager.start_job(job.id):
                jobs.append(job.to_dict())

    if not jobs:
        return jsonify({"error": "Failed to start any attacks"}), 500

    return jsonify({"message": f"Started {len(jobs)} attacks", "jobs": jobs}), 202
