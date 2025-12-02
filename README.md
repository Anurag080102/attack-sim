# Attack-Sim

**Application Automatic Attacks Simulation Tool**

A web-based security testing tool with a simple GUI that enables automated simulation of common attack vectors including brute force attacks, dictionary attacks, and OWASP Top 10 vulnerabilities.

## ⚠️ Disclaimer

> **WARNING**: This tool is intended for **authorized security testing only**. Only use against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Features

- **Target Configuration**: Input target URL/IP and configure connection parameters
- **Attack Selection**: Choose from available attack modules via UI
- **Brute Force Attack**: Automated credential guessing with configurable parameters
- **Dictionary Attack**: Password cracking using wordlist files
- **OWASP Top 10 Scanner**: Automated detection of OWASP Top 10 vulnerabilities
- **Real-time Results**: Live display of attack progress and findings
- **Report Generation**: Export findings to JSON/HTML format

## OWASP Top 10 Attack Modules

| ID  | Vulnerability              | Detection Method                             |
| --- | -------------------------- | -------------------------------------------- |
| A01 | Broken Access Control      | Authorization bypass attempts, IDOR testing |
| A02 | Cryptographic Failures     | TLS/SSL analysis, weak cipher detection      |
| A03 | Injection                  | SQL, XSS, Command injection payloads         |
| A04 | Insecure Design            | Business logic flaw detection                |
| A05 | Security Misconfiguration  | Header analysis, default credentials         |
| A06 | Vulnerable Components      | Version fingerprinting, CVE matching         |
| A07 | Authentication Failures    | Session analysis, brute force                |
| A08 | Integrity Failures         | Deserialization, unsigned data detection     |
| A09 | Logging & Monitoring       | Error disclosure, debug info leakage         |
| A10 | SSRF                       | Server-side request forgery testing          |

## Quick Start

### Prerequisites

- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/Anurag080102/attack-sim.git
cd attack-sim

# Install dependencies using uv
uv sync

# Or install with development dependencies
uv sync --all-extras
```

### Running the Application

```bash
# Start the Flask development server
uv run python run.py

# Open your browser to http://localhost:5000
```

## Project Structure

```
attack-sim/
├── app/                    # Flask application
│   ├── __init__.py        # App factory
│   ├── config.py          # Configuration classes
│   ├── routes/            # API routes
│   ├── static/            # CSS, JS files
│   └── templates/         # HTML templates
├── attacks/               # Attack modules
│   ├── __init__.py       # Attack registry
│   └── owasp/            # OWASP Top 10 scanners
├── wordlists/            # Password/username lists
├── reports/              # Generated reports
├── tests/                # Unit tests
├── requirements.txt      # Python dependencies
└── run.py               # Entry point
```

## Technology Stack

- **Backend**: Python 3.11+ with Flask
- **Frontend**: HTML5 + CSS3 + Vanilla JavaScript
- **HTTP Client**: Requests library

## Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run specific test file
uv run pytest tests/test_attacks.py

# Run with coverage
uv run pytest --cov=app --cov=attacks
```

### Test Structure

```
tests/
├── test_attacks.py      # Unit tests for attack modules (52 tests)
├── test_routes.py       # Unit tests for API routes (51 tests)
├── test_api_endpoints.py # Manual endpoint testing
└── test_attacks_manual.py # Manual attack testing
```

### Code Formatting

```bash
uv run black .
uv run flake8 .
```

## API Documentation

### Attack Endpoints

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| GET | `/api/attacks` | List all available attacks |
| GET | `/api/attacks/<id>` | Get attack details |
| POST | `/api/attacks/run` | Start an attack execution |
| GET | `/api/attacks/jobs` | List attack jobs |
| GET | `/api/attacks/<job_id>/status` | Get job status |
| GET | `/api/attacks/<job_id>/results` | Get job results |
| POST | `/api/attacks/<job_id>/cancel` | Cancel a running job |

### Report Endpoints

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| GET | `/api/reports` | List all reports |
| GET | `/api/reports/<id>` | Get report details |
| POST | `/api/reports/generate` | Generate a new report |
| GET | `/api/reports/<id>/download` | Download report |
| DELETE | `/api/reports/<id>` | Delete a report |

### Health Endpoint

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| GET | `/health` | Health check endpoint |

## License

This project is for educational purposes only.

## Contributing

See the project specification in `.github/instructions/owasp-attacks-implementation.instructions.md` for development guidelines and the implementation plan.
