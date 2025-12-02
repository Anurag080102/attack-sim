"""
Reports Routes

This module provides API endpoints for report generation, listing,
and downloading. Reports are stored as JSON files.
"""

import json
import os
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Dict, Any, List, Optional

from flask import Blueprint, request, jsonify, send_file, current_app

from app.routes.attacks import attack_manager
from app.validation import (
    validate_required,
    validate_string,
    validate_report_id,
    sanitize_html
)

# Import error handling
from app.errors import ValidationError, NotFoundError, ReportError


reports_bp = Blueprint("reports", __name__)


def get_reports_dir() -> Path:
    """Get the reports directory path."""
    return Path(current_app.config.get("REPORTS_DIR", "reports"))


def ensure_reports_dir() -> Path:
    """Ensure reports directory exists and return its path."""
    reports_dir = get_reports_dir()
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def generate_report_id() -> str:
    """Generate a unique report ID based on timestamp."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_report(report_data: Dict[str, Any], report_id: str) -> Path:
    """
    Save a report to disk.
    
    Args:
        report_data: Report content as dictionary
        report_id: Unique report identifier
        
    Returns:
        Path to saved report file
    """
    reports_dir = ensure_reports_dir()
    file_path = reports_dir / f"report_{report_id}.json"
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)
    
    return file_path


def load_report(report_id: str) -> Optional[Dict[str, Any]]:
    """
    Load a report from disk.
    
    Args:
        report_id: Report identifier
        
    Returns:
        Report data if found, None otherwise
    """
    reports_dir = get_reports_dir()
    file_path = reports_dir / f"report_{report_id}.json"
    
    if not file_path.exists():
        return None
    
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_report_files() -> List[Dict[str, Any]]:
    """
    List all available report files.
    
    Returns:
        List of report metadata dictionaries
    """
    reports_dir = get_reports_dir()
    
    if not reports_dir.exists():
        return []
    
    reports = []
    for file_path in reports_dir.glob("report_*.json"):
        stat = file_path.stat()
        report_id = file_path.stem.replace("report_", "")
        
        # Try to read basic info from report
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                title = data.get("title", "Untitled Report")
                findings_count = len(data.get("findings", []))
        except (json.JSONDecodeError, KeyError):
            title = "Untitled Report"
            findings_count = 0
        
        reports.append({
            "id": report_id,
            "title": title,
            "filename": file_path.name,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "findings_count": findings_count
        })
    
    # Sort by creation time (newest first)
    reports.sort(key=lambda r: r["created_at"], reverse=True)
    
    return reports


def generate_html_report(report_data: Dict[str, Any]) -> str:
    """
    Generate an HTML report from report data.
    
    Args:
        report_data: Report content dictionary
        
    Returns:
        HTML string
    """
    findings = report_data.get("findings", [])
    
    # Count findings by severity
    severity_counts: Dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Generate findings HTML
    findings_html = ""
    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "info")
        severity_class = f"severity-{severity}"
        
        findings_html += f"""
        <div class="finding {severity_class}">
            <div class="finding-header">
                <span class="finding-number">#{i}</span>
                <span class="finding-title">{finding.get('title', 'Unknown')}</span>
                <span class="finding-severity">{severity.upper()}</span>
            </div>
            <div class="finding-body">
                <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
                <p><strong>Evidence:</strong> <code>{finding.get('evidence', 'N/A')}</code></p>
                <p><strong>Remediation:</strong> {finding.get('remediation', 'N/A')}</p>
            </div>
        </div>
        """
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data.get('title', 'Security Report')} - Attack-Sim</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        header h1 {{ margin-bottom: 10px; }}
        .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px; }}
        .meta-item {{ background: rgba(255,255,255,0.1); padding: 10px; border-radius: 4px; }}
        .meta-label {{ font-size: 0.85em; opacity: 0.8; }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}
        .summary-item {{
            padding: 15px 25px;
            border-radius: 4px;
            text-align: center;
            min-width: 100px;
        }}
        .summary-item.critical {{ background: #ff4444; color: white; }}
        .summary-item.high {{ background: #ff8800; color: white; }}
        .summary-item.medium {{ background: #ffcc00; color: #333; }}
        .summary-item.low {{ background: #88cc00; color: white; }}
        .summary-item.info {{ background: #4488ff; color: white; }}
        .summary-count {{ font-size: 2em; font-weight: bold; }}
        .findings {{ background: white; padding: 20px; border-radius: 8px; }}
        .findings h2 {{ margin-bottom: 20px; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
            border-bottom: 1px solid #ddd;
        }}
        .finding-number {{ font-weight: bold; color: #666; }}
        .finding-title {{ flex: 1; font-weight: 500; }}
        .finding-severity {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .severity-critical .finding-header {{ background: #fff0f0; }}
        .severity-critical .finding-severity {{ background: #ff4444; color: white; }}
        .severity-high .finding-header {{ background: #fff5f0; }}
        .severity-high .finding-severity {{ background: #ff8800; color: white; }}
        .severity-medium .finding-header {{ background: #fffbf0; }}
        .severity-medium .finding-severity {{ background: #ffcc00; color: #333; }}
        .severity-low .finding-header {{ background: #f5fff0; }}
        .severity-low .finding-severity {{ background: #88cc00; color: white; }}
        .severity-info .finding-header {{ background: #f0f5ff; }}
        .severity-info .finding-severity {{ background: #4488ff; color: white; }}
        .finding-body {{ padding: 15px; }}
        .finding-body p {{ margin-bottom: 10px; }}
        .finding-body code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; word-break: break-all; }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 {report_data.get('title', 'Security Report')}</h1>
            <p>Generated by Attack-Sim Security Testing Tool</p>
            <div class="meta">
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div>{report_data.get('target', 'N/A')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Attack Type</div>
                    <div>{report_data.get('attack_name', 'N/A')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Generated</div>
                    <div>{report_data.get('generated_at', 'N/A')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Total Findings</div>
                    <div>{len(findings)}</div>
                </div>
            </div>
        </header>
        
        <section class="summary">
            <div class="summary-item critical">
                <div class="summary-count">{severity_counts.get('critical', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="summary-item high">
                <div class="summary-count">{severity_counts.get('high', 0)}</div>
                <div>High</div>
            </div>
            <div class="summary-item medium">
                <div class="summary-count">{severity_counts.get('medium', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="summary-item low">
                <div class="summary-count">{severity_counts.get('low', 0)}</div>
                <div>Low</div>
            </div>
            <div class="summary-item info">
                <div class="summary-count">{severity_counts.get('info', 0)}</div>
                <div>Info</div>
            </div>
        </section>
        
        <section class="findings">
            <h2>Findings</h2>
            {findings_html if findings_html else '<p>No findings in this report.</p>'}
        </section>
        
        <footer>
            <p>⚠️ This report is intended for authorized security testing only.</p>
            <p>Attack-Sim &copy; 2025</p>
        </footer>
    </div>
</body>
</html>"""
    
    return html


# API Endpoints

@reports_bp.route("/reports", methods=["GET"])
def list_reports():
    """
    List all saved reports.
    
    Returns:
        JSON list of report metadata
    """
    reports = list_report_files()
    return jsonify({
        "reports": reports,
        "total": len(reports)
    })


@reports_bp.route("/reports/<report_id>", methods=["GET"])
def get_report(report_id: str):
    """
    Get a specific report by ID.
    
    Args:
        report_id: Report identifier
        
    Returns:
        JSON with report data or 404 error
    """
    report = load_report(report_id)
    
    if report is None:
        return jsonify({"error": f"Report '{report_id}' not found"}), 404
    
    return jsonify(report)


@reports_bp.route("/reports/<report_id>/download", methods=["GET"])
def download_report(report_id: str):
    """
    Download a report file.
    
    Args:
        report_id: Report identifier
        
    Query parameters:
        format: 'json' or 'html' (default: json)
        
    Returns:
        File download
    """
    # Validate format parameter
    report_format = request.args.get("format", "json").lower()
    if report_format not in ["json", "html"]:
        return jsonify({"error": "format must be 'json' or 'html'"}), 400
    
    report = load_report(report_id)
    
    if report is None:
        return jsonify({"error": f"Report '{report_id}' not found"}), 404
    
    if report_format == "html":
        html_content = generate_html_report(report)
        
        # Create buffer for HTML download
        buffer = BytesIO(html_content.encode("utf-8"))
        
        return send_file(
            buffer,
            mimetype="text/html",
            as_attachment=True,
            download_name=f"report_{report_id}.html"
        )
    else:
        # JSON download
        reports_dir = get_reports_dir()
        file_path = reports_dir / f"report_{report_id}.json"
        
        return send_file(
            file_path,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"report_{report_id}.json"
        )


@reports_bp.route("/reports/generate", methods=["POST"])
def generate_report():
    """
    Generate a report from an attack job.
    
    Request body:
        {
            "job_id": "uuid-of-completed-job",
            "title": "Optional custom title"
        }
        
    Returns:
        JSON with report ID and metadata
    """
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    # Validate required fields
    try:
        validate_required(data, ["job_id"])
    except ValidationError as e:
        return jsonify({"error": e.message}), 400
    
    job_id = data.get("job_id")
    
    # Validate job_id format (UUID)
    try:
        job_id = validate_string(job_id, "job_id", min_length=1, max_length=100)
    except ValidationError as e:
        return jsonify({"error": e.message}), 400
    
    # Validate title if provided
    title = data.get("title")
    if title:
        try:
            title = validate_string(title, "title", min_length=1, max_length=200)
        except ValidationError as e:
            return jsonify({"error": e.message}), 400
    
    # Get job from attack manager
    job = attack_manager.get_job(job_id)
    if job is None:
        return jsonify({"error": f"Job '{job_id}' not found"}), 404
    
    # Get findings
    findings = attack_manager.get_job_findings(job_id) or []
    
    # Generate report data
    report_id = generate_report_id()
    if not title:
        title = f"{job.attack_name} Report - {job.target}"
    
    report_data = {
        "id": report_id,
        "title": title,
        "job_id": job_id,
        "attack_id": job.attack_id,
        "attack_name": job.attack_name,
        "target": job.target,
        "config": job.config,
        "status": job.status.value,
        "generated_at": datetime.now().isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {}
        }
    }
    
    # Count by severity
    for finding in findings:
        severity = finding.get("severity", "info")
        report_data["summary"]["by_severity"][severity] = \
            report_data["summary"]["by_severity"].get(severity, 0) + 1
    
    # Save report
    file_path = save_report(report_data, report_id)
    
    return jsonify({
        "message": "Report generated successfully",
        "report_id": report_id,
        "file_path": str(file_path),
        "title": title,
        "findings_count": len(findings)
    }), 201


@reports_bp.route("/reports/<report_id>", methods=["DELETE"])
def delete_report(report_id: str):
    """
    Delete a report.
    
    Args:
        report_id: Report identifier
        
    Returns:
        JSON with deletion status
    """
    reports_dir = get_reports_dir()
    file_path = reports_dir / f"report_{report_id}.json"
    
    if not file_path.exists():
        return jsonify({"error": f"Report '{report_id}' not found"}), 404
    
    os.remove(file_path)
    
    return jsonify({"message": f"Report '{report_id}' deleted successfully"})
