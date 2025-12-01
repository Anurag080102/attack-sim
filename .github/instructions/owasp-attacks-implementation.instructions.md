# Attack-Sim: Application Automatic Attacks Simulation Tool

## Project Overview

A web-based security testing tool with a simple GUI that enables automated simulation of common attack vectors including brute force attacks, dictionary attacks, and OWASP Top 10 vulnerabilities.

---

## Functional Specifications

### Core Features

| Feature | Description | Priority |
|---------|-------------|----------|
| **Target Configuration** | Input target URL/IP and configure connection parameters | High |
| **Attack Selection** | Choose from available attack modules via UI | High |
| **Brute Force Attack** | Automated credential guessing with configurable parameters | High |
| **Dictionary Attack** | Password cracking using wordlist files | High |
| **OWASP Top 10 Scanner** | Automated detection of OWASP Top 10 vulnerabilities | High |
| **Real-time Results** | Live display of attack progress and findings | Medium |
| **Report Generation** | Export findings to JSON/HTML format | Medium |
| **Attack History** | View previous scan results | Low |

### OWASP Top 10 Attack Modules

| ID | Vulnerability | Detection Method |
|----|---------------|------------------|
| A01 | Broken Access Control | Authorization bypass attempts, IDOR testing |
| A02 | Cryptographic Failures | TLS/SSL analysis, weak cipher detection |
| A03 | Injection | SQL, XSS, Command injection payloads |
| A04 | Insecure Design | Business logic flaw detection |
| A05 | Security Misconfiguration | Header analysis, default credentials |
| A06 | Vulnerable Components | Version fingerprinting, CVE matching |
| A07 | Authentication Failures | Session analysis, brute force |
| A08 | Integrity Failures | Deserialization, unsigned data detection |
| A09 | Logging & Monitoring | Error disclosure, debug info leakage |
| A10 | SSRF | Server-side request forgery testing |

### User Interface Requirements

- **Dashboard**: Overview of available attacks and recent scans
- **Target Input**: URL/IP input with validation
- **Attack Configuration**: Per-attack parameter settings
- **Progress Display**: Real-time attack status with progress bar
- **Results Panel**: Categorized findings with severity levels
- **Export Options**: Download results as JSON/HTML

---

## Technical Specifications

### Technology Stack

| Component | Technology | Justification |
|-----------|------------|---------------|
| Backend | Python 3.11+ | Attack modules already in Python |
| Web Framework | Flask | Lightweight, simple, sufficient for GUI |
| Frontend | HTML5 + CSS3 + Vanilla JS | Simple, no build step required |
| HTTP Client | Requests | Standard Python HTTP library |
| Async Tasks | Threading | Background attack execution |
| Data Format | JSON | API responses and report storage |

### Project Structure

```
attack-sim/
├── .github/
│   └── instructions/
│       └── owasp-attacks-implementation.instructions.md
│
├── app/
│   ├── __init__.py                 # Flask app factory
│   ├── main.py                     # Entry point
│   ├── config.py                   # Application configuration
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── dashboard.py            # Dashboard routes
│   │   ├── attacks.py              # Attack execution API
│   │   └── reports.py              # Report generation API
│   │
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── app.js
│   │
│   └── templates/
│       ├── base.html               # Base template
│       ├── dashboard.html          # Main dashboard
│       ├── attack_config.html      # Attack configuration
│       └── results.html            # Results display
│
├── attacks/
│   ├── __init__.py                 # Attack module registry
│   ├── base.py                     # Base attack class
│   ├── bruteforce.py               # Brute force attack
│   ├── dictionary.py               # Dictionary attack
│   │
│   └── owasp/
│       ├── __init__.py
│       ├── base_owasp.py           # Base OWASP scanner class
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
├── wordlists/
│   ├── common_passwords.txt
│   └── common_usernames.txt
│
├── reports/                        # Generated reports (gitignored)
│   └── .gitkeep
│
├── tests/
│   ├── __init__.py
│   ├── test_attacks.py
│   └── test_routes.py
│
├── .gitignore
├── requirements.txt
├── README.md
└── run.py                          # Convenience script to run app
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard page |
| GET | `/api/attacks` | List available attacks |
| POST | `/api/attacks/run` | Execute an attack |
| GET | `/api/attacks/status/<id>` | Get attack status |
| GET | `/api/attacks/results/<id>` | Get attack results |
| GET | `/api/reports` | List saved reports |
| GET | `/api/reports/<id>` | Download specific report |

### Attack Module Interface

All attack modules must implement the following interface:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Generator

class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str

class BaseAttack(ABC):
    name: str
    description: str
    
    @abstractmethod
    def configure(self, **kwargs) -> None:
        """Configure attack parameters."""
        pass
    
    @abstractmethod
    def run(self, target: str) -> Generator[Finding, None, None]:
        """Execute the attack and yield findings."""
        pass
    
    @abstractmethod
    def get_progress(self) -> float:
        """Return progress as percentage (0-100)."""
        pass
```

---

## Git Workflow & Conventions

### Branch Strategy

| Branch Type | Naming Convention | Purpose |
|-------------|-------------------|---------|
| Main | `main` | Stable, production-ready code |
| Feature | `feature/<feature-name>` | New features |
| Bugfix | `bugfix/<issue-description>` | Bug fixes |
| Refactor | `refactor/<scope>` | Code refactoring |

### Commit Message Format

```
<type>(<operational-scope>): <Title>.

- <Bullet point 1>
- <Bullet point 2>
- <Bullet point 3>
.
.
.

Refs: #<local-branch-name>
```

#### Commit Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style changes (formatting, no logic change) |
| `refactor` | Code refactoring |
| `test` | Adding or updating tests |
| `chore` | Maintenance tasks, dependencies |
| `init` | Initial setup or scaffolding |

#### Examples

```bash
git commit -m "feat(bruteforce): Add configurable thread count.

- Add max_threads parameter to BruteForceAttack class
- Implement ThreadPoolExecutor for concurrent requests
- Add thread count slider to attack configuration UI

Refs: #feature/bruteforce-attack"
```

```bash
git commit -m "init(project): Set up Flask application structure.

- Create app/ directory with Flask factory pattern
- Add base templates and static files
- Configure requirements.txt with dependencies

Refs: #feature/project-setup"
```

### ⚠️ CRITICAL: Atomic Commit Rule

> **After completing each TODO item, you MUST:**
> 1. Stage the relevant changes: `git add <files>`
> 2. Create an atomic commit following the format above
> 3. Update this TODO list by checking off the completed item
> 4. Commit the TODO update: `git commit -m "docs(todo): Mark <item> as complete. Refs: #<branch>"`

---

## Implementation Plan - TODO List

### Phase 1: Project Setup
**Branch: `feature/project-setup`**

- [x] **1.1** Delete existing `src/` and `worker/` directories
- [x] **1.2** Create new project structure (directories only)
- [x] **1.3** Create `requirements.txt` with dependencies
- [x] **1.4** Create `.gitignore` for Python project
- [x] **1.5** Create `README.md` with project description
- [x] **1.6** Create Flask app factory in `app/__init__.py`
- [x] **1.7** Create `app/config.py` with configuration classes
- [ ] **1.8** Create `run.py` entry point script
- [ ] **1.9** Verify Flask app runs with "Hello World" route

### Phase 2: Base Attack Framework
**Branch: `feature/attack-framework`**

- [ ] **2.1** Create `attacks/base.py` with `BaseAttack` abstract class
- [ ] **2.2** Create `Finding` and `Severity` dataclasses
- [ ] **2.3** Create `attacks/__init__.py` with attack registry
- [ ] **2.4** Create `attacks/owasp/base_owasp.py` with `BaseOWASPAttack` class
- [ ] **2.5** Create `attacks/owasp/__init__.py` with OWASP registry

### Phase 3: Core Attacks Implementation
**Branch: `feature/core-attacks`**

- [ ] **3.1** Implement `attacks/bruteforce.py`
- [ ] **3.2** Implement `attacks/dictionary.py`
- [ ] **3.3** Create `wordlists/common_passwords.txt` (top 100 passwords)
- [ ] **3.4** Create `wordlists/common_usernames.txt` (common usernames)
- [ ] **3.5** Test brute force attack manually

### Phase 4: OWASP Attack Modules
**Branch: `feature/owasp-attacks`**

- [ ] **4.1** Implement `a01_broken_access.py` - Broken Access Control
- [ ] **4.2** Implement `a02_crypto_failures.py` - Cryptographic Failures
- [ ] **4.3** Implement `a03_injection.py` - Injection (SQL, XSS, Command)
- [ ] **4.4** Implement `a04_insecure_design.py` - Insecure Design
- [ ] **4.5** Implement `a05_security_misconfig.py` - Security Misconfiguration
- [ ] **4.6** Implement `a06_outdated_components.py` - Vulnerable Components
- [ ] **4.7** Implement `a07_auth_failures.py` - Auth Failures
- [ ] **4.8** Implement `a08_integrity_failures.py` - Integrity Failures
- [ ] **4.9** Implement `a09_logging_monitoring.py` - Logging/Monitoring
- [ ] **4.10** Implement `a10_ssrf.py` - SSRF Detection

### Phase 5: Web GUI - Backend
**Branch: `feature/web-backend`**

- [ ] **5.1** Create `app/routes/__init__.py` with blueprint registration
- [ ] **5.2** Create `app/routes/dashboard.py` with index route
- [ ] **5.3** Create `app/routes/attacks.py` with attack API endpoints
- [ ] **5.4** Implement attack execution in background thread
- [ ] **5.5** Create `app/routes/reports.py` with report endpoints
- [ ] **5.6** Add attack status tracking with unique IDs
- [ ] **5.7** Test all API endpoints with curl/Postman

### Phase 6: Web GUI - Frontend
**Branch: `feature/web-frontend`**

- [ ] **6.1** Create `app/templates/base.html` with common layout
- [ ] **6.2** Create `app/static/css/style.css` with styling
- [ ] **6.3** Create `app/templates/dashboard.html` with attack cards
- [ ] **6.4** Create `app/templates/attack_config.html` for parameters
- [ ] **6.5** Create `app/templates/results.html` for findings display
- [ ] **6.6** Create `app/static/js/app.js` with AJAX functionality
- [ ] **6.7** Implement real-time progress updates via polling
- [ ] **6.8** Add export buttons for JSON/HTML reports

### Phase 7: Testing & Polish
**Branch: `feature/testing`**

- [ ] **7.1** Create `tests/test_attacks.py` with attack unit tests
- [ ] **7.2** Create `tests/test_routes.py` with route tests
- [ ] **7.3** Add input validation to all endpoints
- [ ] **7.4** Add error handling and user-friendly messages
- [ ] **7.5** Final UI polish and responsiveness fixes

### Phase 8: Documentation & Release
**Branch: `feature/documentation`**

- [ ] **8.1** Update `README.md` with full usage instructions
- [ ] **8.2** Add screenshots to documentation
- [ ] **8.3** Create `CONTRIBUTING.md` for future contributors
- [ ] **8.4** Final code review and cleanup
- [ ] **8.5** Merge all features to `main`

---

## Dependencies

### requirements.txt

```
Flask==3.0.0
requests==2.31.0
python-dotenv==1.0.0
Werkzeug==3.0.1
```

### Development Dependencies

```
pytest==7.4.3
pytest-flask==1.3.0
black==23.12.1
flake8==6.1.0
```

---

## Security Considerations

> ⚠️ **WARNING**: This tool is intended for **authorized security testing only**.

1. **Legal Compliance**: Only use against systems you own or have explicit permission to test
2. **Rate Limiting**: Implement delays to avoid overwhelming target systems
3. **Logging**: Log all attack attempts for audit purposes
4. **Input Validation**: Sanitize all user inputs to prevent self-exploitation
5. **No Credential Storage**: Never persist captured credentials

---

## Quick Start (After Implementation)

```bash
# Clone the repository
git clone https://github.com/Anurag080102/attack-sim.git
cd attack-sim

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py

# Open browser to http://localhost:5000
```

---

## Progress Tracking

| Phase | Status | Branch | Completion Date |
|-------|--------|--------|-----------------|
| Phase 1: Project Setup | ⬜ Not Started | `feature/project-setup` | - |
| Phase 2: Attack Framework | ⬜ Not Started | `feature/attack-framework` | - |
| Phase 3: Core Attacks | ⬜ Not Started | `feature/core-attacks` | - |
| Phase 4: OWASP Attacks | ⬜ Not Started | `feature/owasp-attacks` | - |
| Phase 5: Web Backend | ⬜ Not Started | `feature/web-backend` | - |
| Phase 6: Web Frontend | ⬜ Not Started | `feature/web-frontend` | - |
| Phase 7: Testing | ⬜ Not Started | `feature/testing` | - |
| Phase 8: Documentation | ⬜ Not Started | `feature/documentation` | - |

---

*Last Updated: 2025-12-01*
