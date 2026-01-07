# Attack-Sim

**Application Automatic Attacks Simulation Tool**

A web-based security testing tool with a simple GUI that enables automated simulation of OWASP Top 10 vulnerabilities.

---

## ⚠️ Legal Disclaimer

> **WARNING**: This tool is intended for **authorized security testing only**.
> 
> - Only use against systems you **own** or have **explicit written permission** to test
> - Unauthorized access to computer systems is **illegal** and may result in criminal prosecution
> - The authors assume **no liability** for misuse of this tool
> - Always obtain proper authorization before conducting security assessments

---

## 🎯 Legal Testing Resources

Use these **intentionally vulnerable applications** and platforms to safely test Attack-Sim:

### General-Purpose Vulnerable Applications

| Resource | URL | Description |
|----------|-----|-------------|
| **OWASP WebGoat** | https://owasp.org/www-project-webgoat/ | Official OWASP training app, covers all Top 10 |
| **DVWA** | https://github.com/digininja/DVWA | Damn Vulnerable Web Application |
| **OWASP Juice Shop** | https://demo.owasp-juice.shop/ | Modern vulnerable app with 100+ challenges |
| **HackTheBox** | https://www.hackthebox.com | Legal CTF platform with vulnerable machines |
| **TryHackMe** | https://tryhackme.com | Guided hacking labs and rooms |
| **PortSwigger Web Security Academy** | https://portswigger.net/web-security | Free labs for all OWASP categories |
| **VulnHub** | https://www.vulnhub.com | Downloadable vulnerable VMs |
| **CryptoHack** | https://cryptohack.org | Cryptography-focused challenges |

### Per-Attack Testing Targets

| Attack Module | Recommended Test Target |
|---------------|------------------------|
| **A01: Broken Access Control** | [PortSwigger Access Control Labs](https://portswigger.net/web-security/access-control) |
| **A02: Cryptographic Failures** | [CryptoHack](https://cryptohack.org), OWASP Juice Shop |
| **A03: Injection** | [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection) |
| **A04: Insecure Design** | OWASP Juice Shop, WebGoat |
| **A05: Security Misconfiguration** | [VulnHub VMs](https://www.vulnhub.com), DVWA |
| **A06: Vulnerable Components** | OWASP Juice Shop, WebGoat |
| **A07: Authentication Failures** | [PortSwigger Authentication Labs](https://portswigger.net/web-security/authentication) |
| **A08: Integrity Failures** | OWASP Juice Shop (JWT challenges) |
| **A09: Logging/Monitoring Failures** | Local test environments, DVWA |
| **A10: SSRF** | [PortSwigger SSRF Labs](https://portswigger.net/web-security/ssrf) |

### 🐳 Self-Hosted Options (Docker)

Run vulnerable applications locally for safe testing:

```bash
# DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# OWASP Juice Shop
docker run --rm -p 3000:3000 bkimminich/juice-shop

# WebGoat
docker run -p 8080:8080 -p 9090:9090 webgoat/webgoat
```

> **Tip**: For beginners, start with [PortSwigger Web Security Academy](https://portswigger.net/web-security) - it offers free, isolated labs covering all OWASP Top 10 categories with no setup required.

---

## Table of Contents

- [Attack-Sim](#attack-sim)
  - [⚠️ Legal Disclaimer](#️-legal-disclaimer)
  - [🎯 Legal Testing Resources](#-legal-testing-resources)
    - [General-Purpose Vulnerable Applications](#general-purpose-vulnerable-applications)
    - [Per-Attack Testing Targets](#per-attack-testing-targets)
    - [🐳 Self-Hosted Options (Docker)](#-self-hosted-options-docker)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [OWASP Top 10 Attack Modules](#owasp-top-10-attack-modules)
  - [Quick Start](#quick-start)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Installation Steps](#installation-steps)
    - [Verify Installation](#verify-installation)
  - [Usage Guide](#usage-guide)
    - [Web Interface](#web-interface)
    - [Running Attacks](#running-attacks)
      - [Step 1: Select an Attack](#step-1-select-an-attack)
      - [Step 2: Configure the Attack](#step-2-configure-the-attack)
      - [Step 3: Start the Attack](#step-3-start-the-attack)
    - [Attack Configuration](#attack-configuration)
      - [OWASP Scanner Options](#owasp-scanner-options)
    - [Viewing Results](#viewing-results)
      - [Severity Levels](#severity-levels)
      - [Finding Details](#finding-details)
    - [Generating Reports](#generating-reports)
  - [Attack Modules Reference](#attack-modules-reference)
    - [OWASP Top 10 Scanners](#owasp-top-10-scanners)
      - [A01 - Broken Access Control](#a01---broken-access-control)
      - [A02 - Cryptographic Failures](#a02---cryptographic-failures)
      - [A03 - Injection](#a03---injection)
      - [A04 - Insecure Design](#a04---insecure-design)
      - [A05 - Security Misconfiguration](#a05---security-misconfiguration)
      - [A06 - Vulnerable Components](#a06---vulnerable-components)
      - [A07 - Authentication Failures](#a07---authentication-failures)
      - [A08 - Integrity Failures](#a08---integrity-failures)
      - [A09 - Logging \& Monitoring](#a09---logging--monitoring)
      - [A10 - SSRF](#a10---ssrf)
  - [API Documentation](#api-documentation)
    - [Base URL](#base-url)
    - [Attack Endpoints](#attack-endpoints)
    - [Report Endpoints](#report-endpoints)
    - [Example: Run an Attack](#example-run-an-attack)
    - [Example: Check Job Status](#example-check-job-status)
  - [Configuration](#configuration)
    - [Environment Variables](#environment-variables)
    - [Configuration Files](#configuration-files)
    - [Running in Production](#running-in-production)
  - [Project Structure](#project-structure)
  - [Development](#development)
    - [Setting Up Development Environment](#setting-up-development-environment)
    - [Running Tests](#running-tests)
    - [Test Suite Overview](#test-suite-overview)
    - [Code Quality](#code-quality)
    - [Adding a New Attack Module](#adding-a-new-attack-module)
  - [Troubleshooting](#troubleshooting)
    - [Common Issues](#common-issues)
      - [Application won't start](#application-wont-start)
      - [Attacks timeout immediately](#attacks-timeout-immediately)
      - [No findings reported](#no-findings-reported)
      - [Import errors](#import-errors)
    - [Getting Help](#getting-help)
  - [Contributing](#contributing)
    - [Development Workflow](#development-workflow)
    - [Commit Message Format](#commit-message-format)
  - [License](#license)
  - [Acknowledgments](#acknowledgments)

---

## Features

| Feature | Description |
|---------|-------------|
| **Target Configuration** | Input target URL/IP and configure connection parameters |
| **Attack Selection** | Choose from available OWASP Top 10 attack modules via intuitive UI |
| **OWASP Top 10 Scanner** | Automated detection of OWASP Top 10 (2021) vulnerabilities |
| **Real-time Progress** | Live display of attack progress with percentage completion |
| **Severity Classification** | Findings categorized by severity (Critical, High, Medium, Low, Info) |
| **Report Generation** | Export findings to JSON format with timestamps |
| **Attack History** | View and manage previous scan results |
| **Job Management** | Cancel running attacks, view job status |

---

## OWASP Top 10 Attack Modules

| ID  | Vulnerability              | Detection Method                             |
| --- | -------------------------- | -------------------------------------------- |
| A01 | Broken Access Control      | Authorization bypass attempts, IDOR testing, path traversal |
| A02 | Cryptographic Failures     | TLS/SSL analysis, weak cipher detection, certificate validation |
| A03 | Injection                  | SQL injection, XSS, Command injection payloads |
| A04 | Insecure Design            | Business logic flaw detection, rate limiting analysis |
| A05 | Security Misconfiguration  | Header analysis, default credentials, debug mode detection |
| A06 | Vulnerable Components      | Version fingerprinting, CVE matching, outdated library detection |
| A07 | Authentication Failures    | Session analysis, weak password policy, brute force resistance |
| A08 | Integrity Failures         | Deserialization tests, unsigned data detection, CI/CD analysis |
| A09 | Logging & Monitoring       | Error disclosure, debug info leakage, verbose error detection |
| A10 | SSRF                       | Server-side request forgery testing, internal network probing |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Anurag080102/attack-sim.git
cd attack-sim

# Install dependencies using uv
uv sync

# Run the application
uv run src/main/python/main.py

# Open browser to http://localhost:5000
```

---

## Installation

### Prerequisites

- **Python 3.11** or higher
- **[uv](https://docs.astral.sh/uv/)** - Fast Python package manager
- Git (for cloning the repository)

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/Anurag080102/attack-sim.git
cd attack-sim

# Install dependencies
uv sync

# Install with development dependencies (for testing/contributing)
uv sync --all-extras
```

### Verify Installation

```bash
# Run the application
uv run src/main/python/main.py

# You should see:
# ==================================================
#   Attack-Sim - Security Testing Tool
# ==================================================
#   Running on: http://127.0.0.1:5000
#   Configuration: development
# ==================================================
```

---

## Usage Guide

### Web Interface

1. **Start the application**:
   ```bash
   uv run src/main/python/main.py
   ```

2. **Open your browser** to `http://localhost:5000`

3. **Dashboard Overview**:
   - View available OWASP Top 10 attack modules
   - See recent attack jobs and their status
   - Access reports and settings

### Running Attacks

#### Step 1: Select an Attack

From the dashboard, click on an attack card to configure it:
- **OWASP Top 10 Scanners**: A01 through A10 vulnerability scanners

#### Step 2: Configure the Attack

Enter the required parameters:

| Field | Description | Example |
|-------|-------------|---------|
| **Target URL** | The base URL of the target application | `http://target.example.com` |
| **Username** | Target username (for auth attacks) | `admin` |
| **Login URL** | Full path to login endpoint | `/login` or `/api/auth` |
| **Additional Options** | Attack-specific parameters | Thread count, delays, etc. |

#### Step 3: Start the Attack

1. Click **"Run Attack"** to start
2. Monitor progress in real-time with the progress bar
3. Findings appear as they are discovered
4. Use **"Cancel"** to stop a running attack

### Attack Configuration

#### OWASP Scanner Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `timeout` | integer | `10` | Request timeout |
| `delay` | float | `0.5` | Delay between requests |
| `follow_redirects` | boolean | `true` | Follow HTTP redirects |
| `max_depth` | integer | `2` | Crawl depth for discovery |

### Viewing Results

#### Severity Levels

| Severity | Icon | Description |
|----------|------|-------------|
| **Critical** | 🔴 | Immediate exploitation possible, high impact |
| **High** | 🟠 | Significant vulnerability, should be fixed soon |
| **Medium** | 🟡 | Moderate risk, plan for remediation |
| **Low** | 🟢 | Minor issue, fix when convenient |
| **Info** | 🔵 | Informational finding, no immediate risk |

#### Finding Details

Each finding includes:
- **Title**: Brief description of the vulnerability
- **Severity**: Risk level classification
- **Description**: Detailed explanation
- **Evidence**: Proof of the vulnerability
- **Remediation**: Steps to fix the issue
- **Metadata**: Additional technical details

### Generating Reports

1. After an attack completes, click **"Generate Report"**
2. Select the format (JSON)
3. Reports are saved to the `reports/` directory
4. Download or view reports from the Reports page

---

## Attack Modules Reference

### OWASP Top 10 Scanners

#### A01 - Broken Access Control
Tests for authorization bypass, IDOR, path traversal, and privilege escalation.

#### A02 - Cryptographic Failures
Analyzes TLS/SSL configuration, detects weak ciphers, and validates certificates.

#### A03 - Injection
Tests for SQL injection, XSS (reflected/stored), and OS command injection.

#### A04 - Insecure Design
Detects business logic flaws, missing rate limiting, and insecure workflows.

#### A05 - Security Misconfiguration
Checks security headers, default credentials, debug modes, and exposed files.

#### A06 - Vulnerable Components
Fingerprints software versions and checks for known CVEs.

#### A07 - Authentication Failures
Tests session management, password policies, and brute force protections.

#### A08 - Integrity Failures
Detects insecure deserialization and unsigned data vulnerabilities.

#### A09 - Logging & Monitoring
Identifies error disclosure, debug information leakage, and verbose errors.

#### A10 - SSRF
Tests for server-side request forgery and internal network access.

---

## API Documentation

### Base URL

```
http://localhost:5000/api
```

### Attack Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/attacks` | List all available attacks |
| `GET` | `/attacks/<attack_id>` | Get attack details and options |
| `POST` | `/attacks/run` | Start a new attack job |
| `GET` | `/attacks/jobs` | List all attack jobs |
| `GET` | `/attacks/status/<job_id>` | Get job status and progress |
| `GET` | `/attacks/results/<job_id>` | Get job findings |
| `POST` | `/attacks/cancel/<job_id>` | Cancel a running job |
| `GET` | `/attacks/owasp/categories` | List OWASP attack categories |

### Report Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/reports` | List all saved reports |
| `GET` | `/reports/<report_id>` | Get report details |
| `POST` | `/reports/generate` | Generate a new report |
| `GET` | `/reports/<report_id>/download` | Download report file |
| `DELETE` | `/reports/<report_id>` | Delete a report |

### Example: Run an Attack

**Request**:
```bash
curl -X POST http://localhost:5000/api/attacks/run \
  -H "Content-Type: application/json" \
  -d '{
    "attack_id": "a05",
    "target": "http://target.example.com",
    "config": {
      "timeout": 10,
      "delay": 0.5
    }
  }'
```

**Response**:
```json
{
  "message": "Attack started",
  "job": {
    "id": "abc123-def456-...",
    "attack_id": "a05",
    "attack_name": "Security Misconfiguration Scanner",
    "target": "http://target.example.com",
    "status": "running",
    "progress": 0.0,
    "started_at": "2025-12-02T10:30:00"
  }
}
```

### Example: Check Job Status

**Request**:
```bash
curl http://localhost:5000/api/attacks/status/abc123-def456-...
```

**Response**:
```json
{
  "id": "abc123-def456-...",
  "status": "completed",
  "progress": 100.0,
  "findings_count": 3,
  "completed_at": "2025-12-02T10:35:00"
}
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_CONFIG` | `development` | Configuration mode (development/testing/production) |
| `FLASK_HOST` | `127.0.0.1` | Server host address |
| `FLASK_PORT` | `5000` | Server port |
| `SECRET_KEY` | (auto-generated) | Flask secret key (required in production) |

### Configuration Files

**`app/config.py`** contains configuration classes:
- `DevelopmentConfig`: Debug enabled, relaxed settings
- `TestingConfig`: For running tests
- `ProductionConfig`: Secure settings, requires `SECRET_KEY`

### Running in Production

```bash
# Set required environment variables
export FLASK_CONFIG=production
export SECRET_KEY="your-secure-secret-key"
export FLASK_HOST=0.0.0.0

# Run with a production WSGI server (e.g., gunicorn)
uv add gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app('production')"
```

---

## Project Structure

```
attack-sim/
├── src/
│   ├── main/
│   │   ├── python/
│   │   │   ├── main.py              # Application entry point
│   │   │   ├── app/                 # Flask application
│   │   │   │   ├── __init__.py      # App factory
│   │   │   │   ├── config.py        # Configuration classes
│   │   │   │   ├── errors.py        # Error handlers
│   │   │   │   ├── validation.py    # Input validation
│   │   │   │   ├── routes/
│   │   │   │   │   ├── __init__.py  # Blueprint registration
│   │   │   │   │   ├── dashboard.py # Dashboard routes
│   │   │   │   │   ├── attacks.py   # Attack API endpoints
│   │   │   │   │   └── reports.py   # Report endpoints
│   │   │   │   ├── static/
│   │   │   │   │   ├── css/
│   │   │   │   │   │   └── style.css
│   │   │   │   │   └── js/
│   │   │   │   │       └── app.js
│   │   │   │   └── templates/
│   │   │   │       ├── base.html
│   │   │   │       ├── dashboard.html
│   │   │   │       ├── attack_config.html
│   │   │   │       ├── results.html
│   │   │   │       ├── reports.html
│   │   │   │       └── error.html
│   │   │   └── attacks/             # Attack modules
│   │   │       ├── __init__.py      # Attack registry
│   │   │       ├── base.py          # BaseAttack, Finding, Severity
│   │   │       └── owasp/
│   │   │           ├── __init__.py  # OWASP registry
│   │   │           ├── base_owasp.py
│   │   │           ├── a01_broken_access.py
│   │   │           ├── a02_crypto_failures.py
│   │   │           ├── a03_injection.py
│   │   │           ├── a04_insecure_design.py
│   │   │           ├── a05_security_misconfig.py
│   │   │           ├── a06_outdated_components.py
│   │   │           ├── a07_auth_failures.py
│   │   │           ├── a08_integrity_failures.py
│   │   │           ├── a09_logging_monitoring.py
│   │   │           └── a10_ssrf.py
│   │   └── resources/
│   │       └── wordlists/
│   │           ├── common_passwords.txt
│   │           └── common_usernames.txt
│   └── test/
│       ├── python/
│       │   ├── __init__.py
│       │   ├── conftest.py          # Pytest fixtures
│       │   ├── test_attacks.py      # Attack module tests
│       │   ├── test_routes.py       # Route/API tests
│       │   ├── test_integration.py  # Integration tests
│       │   └── manual_api_test.py   # Manual API testing
│       └── resources/               # Test resources
│
├── target/                          # Build outputs (gitignored)
│   └── reports/                     # Generated reports
│
├── .github/
│   └── instructions/                # Project specifications
│
├── AGENTS.md                        # Agent workflow guide
├── pyproject.toml                   # Project configuration
├── uv.lock                          # Dependency lock file
└── README.md                        # This file
```

---

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/Anurag080102/attack-sim.git
cd attack-sim

# Install with dev dependencies
uv sync --all-extras

# Run tests to verify setup
uv run pytest
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run specific test file
uv run pytest src/tests/python/test_attacks.py

# Run specific test
uv run pytest src/tests/python/test_attacks.py::TestInjectionAttack::test_injection_payloads_exist

# Run with coverage report
uv run pytest --cov=app --cov=attacks --cov-report=html
```

### Test Suite Overview

| Test File | Tests | Description |
|-----------|-------|-------------|
| `test_attacks.py` | 52 | Attack module unit tests |
| `test_routes.py` | 51 | API route tests |
| `test_integration.py` | - | End-to-end integration tests |
| `conftest.py` | - | Shared pytest fixtures |

### Code Quality

```bash
# Format code with Black
uv run ruff format

# Check linting with Flake8
uv run ruff check
```

### Adding a New Attack Module

1. Create a new file in `attacks/` or `attacks/owasp/`
2. Inherit from `BaseAttack` or `BaseOWASPAttack`
3. Implement required methods:
   - `configure(**kwargs)`: Set attack parameters
   - `run(target) -> Generator[Finding]`: Execute attack
   - `get_progress() -> float`: Return progress percentage
4. Register with the appropriate registry using decorator

**Example**:
```python
from attacks.base import BaseAttack, Finding, Severity
from attacks import AttackRegistry

@AttackRegistry.register("my_attack")
class MyAttack(BaseAttack):
    name = "My Custom Attack"
    description = "Description of what this attack does"
    
    def configure(self, **kwargs):
        self._config = {"option": kwargs.get("option", "default")}
    
    def run(self, target):
        yield Finding(
            title="Example Finding",
            severity=Severity.MEDIUM,
            description="Found something",
            evidence="Evidence here",
            remediation="How to fix"
        )
    
    def get_progress(self):
        return self._progress
```

---

## Troubleshooting

### Common Issues

#### Application won't start

```bash
# Check Python version
python --version  # Should be 3.11+

# Verify dependencies
uv sync

# Check for port conflicts
lsof -i :5000  # or netstat -an | grep 5000
```

#### Attacks timeout immediately

- Check if the target is reachable
- Increase the `timeout` configuration
- Verify the target URL is correct (include `http://` or `https://`)

#### No findings reported

- Ensure the target has the vulnerabilities you're testing for
- Check that the login URL and form field names are correct
- Review the success/failure indicators

#### Import errors

```bash
# Reinstall dependencies
uv sync --reinstall
```

### Getting Help

1. Check the logs in the terminal for error messages
2. Review the API response for error details
3. Open an issue on GitHub with:
   - Error message
   - Steps to reproduce
   - Python version and OS

---

## Contributing

We welcome contributions! Please follow these guidelines:

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Write tests for new functionality
5. Run the test suite: `uv run pytest`
6. Commit using conventional format:
   ```
   feat(scope): Short description
   
   - Bullet point 1
   - Bullet point 2
   
   Refs: #feature/my-feature
   ```
7. Push and create a Pull Request

### Commit Message Format

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `style`: Code style changes
- `chore`: Maintenance tasks

---

## License

This project is for **educational purposes only**.

The tool is provided "as-is" without warranty. Users are solely responsible for ensuring their use of this tool complies with applicable laws and regulations.

---

## Acknowledgments

- [OWASP Top 10](https://owasp.org/Top10/) for vulnerability classification
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Requests](https://requests.readthedocs.io/) for HTTP functionality

---

*Last Updated: December 2025*
