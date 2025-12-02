# Attack-Sim

**Application Automatic Attacks Simulation Tool**

A web-based security testing tool with a simple GUI that enables automated simulation of common attack vectors including brute force attacks, dictionary attacks, and OWASP Top 10 vulnerabilities.

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
| **OWASP Juice Shop** | https://owasp.org/www-project-juice-shop/ | Modern vulnerable app with 100+ challenges |
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
  - [⚠️ Disclaimer](#️-disclaimer)
  - [🎯 Legal Testing Resources](#-legal-testing-resources)
    - [General-Purpose Vulnerable Applications](#general-purpose-vulnerable-applications)
    - [Per-Attack Testing Targets](#per-attack-testing-targets)
    - [🐳 Self-Hosted Options (Docker)](#-self-hosted-options-docker)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [OWASP Top 10 Attack Modules](#owasp-top-10-attack-modules)
  - [Quick Start](#quick-start)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Running the Application](#running-the-application)
  - [Project Structure](#project-structure)
  - [Technology Stack](#technology-stack)
  - [Development](#development)
    - [Running Tests](#running-tests)
    - [Test Structure](#test-structure)
    - [Code Formatting](#code-formatting)
  - [API Documentation](#api-documentation)
    - [Attack Endpoints](#attack-endpoints)
    - [Report Endpoints](#report-endpoints)
    - [Health Endpoint](#health-endpoint)
  - [License](#license)
  - [Contributing](#contributing)

---

## Features

| Feature | Description |
|---------|-------------|
| **Target Configuration** | Input target URL/IP and configure connection parameters |
| **Attack Selection** | Choose from available attack modules via intuitive UI |
| **Brute Force Attack** | Automated credential guessing with configurable charset, length, and threading |
| **Dictionary Attack** | Password cracking using customizable wordlist files |
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
uv run python run.py

# Open browser to http://localhost:5000
```

---

## Installation

### Prerequisites

- **Python 3.11** or higher
- **[uv](https://docs.astral.sh/uv/)** (recommended Python package manager)
- Git (for cloning the repository)

### Option 1: Using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/Anurag080102/attack-sim.git
cd attack-sim

# Install dependencies
uv sync

# Install with development dependencies (for testing/contributing)
uv sync --all-extras
```

### Option 2: Using pip

```bash
# Clone the repository
git clone https://github.com/Anurag080102/attack-sim.git
cd attack-sim

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install flask requests python-dotenv werkzeug

# For development
pip install pytest pytest-flask black flake8
```

### Verify Installation

```bash
# Run the application
uv run python run.py  # or: python run.py

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
   uv run python run.py
   ```

2. **Open your browser** to `http://localhost:5000`

3. **Dashboard Overview**:
   - View available attack modules (Core attacks and OWASP scanners)
   - See recent attack jobs and their status
   - Access reports and settings

### Running Attacks

#### Step 1: Select an Attack

From the dashboard, click on an attack card to configure it:
- **Brute Force Attack**: Systematically tries password combinations
- **Dictionary Attack**: Uses wordlists to try common passwords
- **OWASP Scanners**: A01 through A10 vulnerability scanners

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

#### Brute Force Attack Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `username` | string | `admin` | Target username |
| `charset` | string | `a-z0-9` | Characters for password generation |
| `min_length` | integer | `1` | Minimum password length |
| `max_length` | integer | `4` | Maximum password length |
| `login_url` | string | `/login` | Login endpoint path |
| `username_field` | string | `username` | Form field name for username |
| `password_field` | string | `password` | Form field name for password |
| `max_threads` | integer | `5` | Concurrent threads (1-20) |
| `timeout` | integer | `10` | Request timeout in seconds |
| `delay` | float | `0.1` | Delay between requests |
| `success_indicator` | string | - | Text indicating successful login |
| `failure_indicator` | string | `invalid` | Text indicating failed login |

#### Dictionary Attack Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `username` | string | `admin` | Target username |
| `password_wordlist` | file | `wordlists/common_passwords.txt` | Password wordlist file |
| `username_wordlist` | file | - | Username wordlist (for enumeration) |
| `stop_on_success` | boolean | `true` | Stop after finding valid credentials |
| `max_threads` | integer | `5` | Concurrent threads |

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

### Brute Force Attack

**ID**: `bruteforce`

Systematically generates and tests password combinations against a target login endpoint.

**How it works**:
1. Generates passwords using the specified charset and length range
2. Sends login requests with each generated password
3. Analyzes responses to detect successful authentication
4. Supports multi-threaded execution for faster testing

**Example API Request**:
```json
POST /api/attacks/run
{
  "attack_id": "bruteforce",
  "target": "http://target.example.com",
  "config": {
    "username": "admin",
    "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
    "min_length": 1,
    "max_length": 4,
    "max_threads": 5
  }
}
```

### Dictionary Attack

**ID**: `dictionary`

Uses wordlists of common passwords and usernames to discover valid credentials.

**Included Wordlists**:
- `wordlists/common_passwords.txt` - Top 100 common passwords
- `wordlists/common_usernames.txt` - Common usernames

**Custom Wordlists**:
You can use custom wordlists by providing the path:
```json
{
  "config": {
    "password_wordlist": "/path/to/custom_passwords.txt",
    "username_wordlist": "/path/to/custom_users.txt"
  }
}
```

### OWASP Scanners

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
    "attack_id": "dictionary",
    "target": "http://target.example.com",
    "config": {
      "username": "admin",
      "max_threads": 3
    }
  }'
```

**Response**:
```json
{
  "message": "Attack started",
  "job": {
    "id": "abc123-def456-...",
    "attack_id": "dictionary",
    "attack_name": "Dictionary Attack",
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
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app('production')"
```

---

## Project Structure

```
attack-sim/
├── app/                         # Flask application
│   ├── __init__.py             # App factory
│   ├── config.py               # Configuration classes
│   ├── errors.py               # Error handlers
│   ├── validation.py           # Input validation utilities
│   ├── routes/
│   │   ├── __init__.py         # Blueprint registration
│   │   ├── dashboard.py        # Dashboard routes
│   │   ├── attacks.py          # Attack API endpoints
│   │   └── reports.py          # Report endpoints
│   ├── static/
│   │   ├── css/style.css       # Application styles
│   │   └── js/app.js           # Frontend JavaScript
│   └── templates/
│       ├── base.html           # Base template
│       ├── dashboard.html      # Main dashboard
│       ├── attack_config.html  # Attack configuration
│       ├── results.html        # Results display
│       ├── reports.html        # Reports page
│       └── error.html          # Error pages
│
├── attacks/                     # Attack modules
│   ├── __init__.py             # Attack registry
│   ├── base.py                 # BaseAttack class, Finding, Severity
│   ├── bruteforce.py           # Brute force attack
│   ├── dictionary.py           # Dictionary attack
│   └── owasp/
│       ├── __init__.py         # OWASP registry
│       ├── base_owasp.py       # Base OWASP scanner
│       ├── a01_broken_access.py
│       ├── a02_crypto_failures.py
│       ├── a03_injection.py
│       ├── a04_insecure_design.py
│       ├── a05_security_misconfig.py
│       ├── a06_outdated_components.py
│       ├── a07_auth_failures.py
│       ├── a08_integrity_failures.py
│       ├── a09_logging_monitoring.py
│       └── a10_ssrf.py
│
├── wordlists/                   # Wordlist files
│   ├── common_passwords.txt    # Top 100 passwords
│   └── common_usernames.txt    # Common usernames
│
├── reports/                     # Generated reports (gitignored)
│
├── tests/                       # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Pytest fixtures
│   ├── test_attacks.py         # Attack module tests
│   ├── test_routes.py          # Route/API tests
│   ├── test_integration.py     # Integration tests
│   └── test_api_endpoints.py   # Endpoint tests
│
├── .github/
│   └── instructions/           # Project specifications
│
├── pyproject.toml              # Project configuration
├── run.py                      # Application entry point
└── README.md                   # This file
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
uv run pytest tests/test_attacks.py

# Run specific test
uv run pytest tests/test_attacks.py::TestBruteForceAttack::test_password_generation

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
uv run black .

# Check linting with Flake8
uv run flake8 .

# Type checking (if using mypy)
uv run mypy app attacks
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

See `.github/instructions/owasp-attacks-implementation.instructions.md` for detailed guidelines.

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
