"""
A04:2021 - Insecure Design Attack Module.

This module implements detection of insecure design patterns including:
- Missing rate limiting
- Lack of CAPTCHA on sensitive forms
- Predictable resource locations
- Missing anti-automation controls
- Business logic flaws
"""

import re
import time
from typing import Generator, Dict, Any, List

# urljoin removed - not currently used

from attacks.base import Finding, Severity
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase
from attacks.owasp import OWASPRegistry


@OWASPRegistry.register("a04")
class InsecureDesignAttack(BaseOWASPAttack):
    """
    Insecure Design vulnerability scanner.

    Tests for design-level security flaws that indicate missing security controls.
    """

    name = "Insecure Design Scanner"
    description = "Detects insecure design patterns and missing security controls"
    category = OWASPCategory.A04_INSECURE_DESIGN

    # Forms that should have CAPTCHA or rate limiting
    SENSITIVE_FORM_INDICATORS = [
        "login",
        "signin",
        "register",
        "signup",
        "password",
        "reset",
        "forgot",
        "contact",
        "comment",
        "feedback",
        "subscribe",
    ]

    # Predictable/sequential resource patterns
    PREDICTABLE_PATTERNS = [
        "/user/1",
        "/user/2",
        "/account/1",
        "/account/2",
        "/order/1",
        "/order/2",
        "/invoice/1",
        "/invoice/2",
        "/document/1",
        "/document/2",
        "/file/1",
        "/file/2",
        "/download/1",
        "/download/2",
        "/api/v1/users/1",
        "/api/v1/users/2",
    ]

    # Backup/development files that shouldn't exist
    SENSITIVE_FILES = [
        ".git/config",
        ".gitignore",
        ".env",
        ".env.local",
        ".env.production",
        ".env.backup",
        "config.php.bak",
        "config.php.old",
        "wp-config.php.bak",
        "web.config.bak",
        "database.yml",
        "settings.py",
        "secrets.json",
        ".htaccess",
        ".htpasswd",
        "phpinfo.php",
        "info.php",
        "test.php",
        "debug.php",
        "backup.sql",
        "database.sql",
        "dump.sql",
        "backup.zip",
        "backup.tar.gz",
        "site.zip",
        ".DS_Store",
        "Thumbs.db",
        "composer.json",
        "package.json",
        "yarn.lock",
        "Gemfile",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
    ]

    def __init__(self):
        super().__init__()
        self._rate_limit_detected = False

    def configure(self, **kwargs) -> None:
        """
        Configure insecure design attack parameters.

        Args:
            test_rate_limiting: Test for missing rate limiting (default: True)
            test_captcha: Test for missing CAPTCHA (default: True)
            test_predictable: Test for predictable resources (default: True)
            rate_limit_requests: Number of requests to test rate limiting (default: 20)
        """
        super().configure(**kwargs)
        self._config["test_rate_limiting"] = kwargs.get("test_rate_limiting", True)
        self._config["test_captcha"] = kwargs.get("test_captcha", True)
        self._config["test_predictable"] = kwargs.get("test_predictable", True)
        self._config["rate_limit_requests"] = kwargs.get("rate_limit_requests", 20)

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "test_rate_limiting": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for missing rate limiting",
                },
                "test_captcha": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for missing CAPTCHA on sensitive forms",
                },
                "test_predictable": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for predictable resource locations",
                },
                "rate_limit_requests": {
                    "type": "integer",
                    "default": 20,
                    "description": "Number of requests to send when testing rate limiting",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for insecure design."""
        return [
            OWASPTestCase(
                name="Missing Rate Limiting",
                description="Test if rate limiting is implemented",
                category=OWASPCategory.A04_INSECURE_DESIGN,
                payloads=[],
                detection_patterns=["rate limit", "too many requests", "429"],
            ),
            OWASPTestCase(
                name="Missing CAPTCHA",
                description="Check for CAPTCHA on sensitive forms",
                category=OWASPCategory.A04_INSECURE_DESIGN,
                payloads=[],
                detection_patterns=["captcha", "recaptcha", "hcaptcha"],
            ),
            OWASPTestCase(
                name="Predictable Resources",
                description="Test for predictable/sequential resource identifiers",
                category=OWASPCategory.A04_INSECURE_DESIGN,
                payloads=self.PREDICTABLE_PATTERNS,
                detection_patterns=[],
            ),
            OWASPTestCase(
                name="Sensitive Files Exposure",
                description="Check for exposed sensitive files",
                category=OWASPCategory.A04_INSECURE_DESIGN,
                payloads=self.SENSITIVE_FILES,
                detection_patterns=[],
            ),
        ]

    def _test_rate_limiting(self, target: str) -> Generator[Finding, None, None]:
        """Test for missing rate limiting on login/sensitive endpoints."""
        if not self._config.get("test_rate_limiting", True):
            return

        base_url = self._normalize_url(target)

        # Common endpoints that should have rate limiting
        rate_limit_endpoints = [
            "/login",
            "/api/login",
            "/auth/login",
            "/signin",
            "/api/auth",
            "/password/reset",
            "/forgot-password",
            "/api/users",
        ]

        num_requests = self._config.get("rate_limit_requests", 20)

        for endpoint in rate_limit_endpoints:
            if self.is_cancelled():
                return

            test_url = self._build_url(base_url, endpoint)

            # First check if endpoint exists
            initial_response = self._make_request(test_url)
            if not initial_response or initial_response.status_code == 404:
                continue

            # Send multiple rapid requests
            responses = []
            rate_limited = False

            for i in range(num_requests):
                if self.is_cancelled():
                    return

                response = self._make_request(
                    test_url,
                    method="POST",
                    data={"username": f"test{i}@test.com", "password": "testpassword123"},
                )

                if response:
                    responses.append(response.status_code)

                    # Check for rate limiting indicators
                    if response.status_code == 429:
                        rate_limited = True
                        break

                    rate_limit_headers = [
                        "x-ratelimit-limit",
                        "x-ratelimit-remaining",
                        "retry-after",
                        "x-rate-limit-limit",
                    ]

                    for header in rate_limit_headers:
                        if header in [h.lower() for h in response.headers.keys()]:
                            rate_limited = True
                            break

                    if rate_limited:
                        break

                # Small delay to not overwhelm
                time.sleep(0.05)

            if not rate_limited and len(responses) >= num_requests:
                yield Finding(
                    title="Missing Rate Limiting",
                    severity=Severity.MEDIUM,
                    description=f"No rate limiting detected on endpoint '{endpoint}'. "
                    "This could allow brute force attacks.",
                    evidence=f"Sent {num_requests} requests without being rate limited. "
                    f"Response codes: {list(set(responses))}",
                    remediation="Implement rate limiting on authentication endpoints. "
                    "Use exponential backoff and account lockout policies. "
                    "Consider using a WAF with rate limiting capabilities.",
                    metadata={
                        "endpoint": endpoint,
                        "requests_sent": num_requests,
                        "response_codes": list(set(responses)),
                    },
                )

        self.set_progress(25)

    def _test_captcha(self, target: str) -> Generator[Finding, None, None]:
        """Test for missing CAPTCHA on sensitive forms."""
        if not self._config.get("test_captcha", True):
            return

        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        # Find all forms and check for CAPTCHA
        forms = self._extract_forms(response.text)

        # Also check common pages for forms
        pages_to_check = [
            "/login",
            "/register",
            "/signup",
            "/contact",
            "/forgot-password",
            "/reset-password",
            "/feedback",
        ]

        for page in pages_to_check:
            if self.is_cancelled():
                return

            page_url = self._build_url(base_url, page)
            page_response = self._make_request(page_url)

            if page_response and page_response.status_code == 200:
                page_forms = self._extract_forms(page_response.text)
                for form in page_forms:
                    form["page"] = page
                forms.extend(page_forms)

            time.sleep(self._delay_between_requests)

        captcha_patterns = [
            r"captcha",
            r"recaptcha",
            r"hcaptcha",
            r"g-recaptcha",
            r"h-captcha",
            r"cf-turnstile",
            r"data-sitekey",
        ]

        for form in forms:
            form_action = form.get("action", "").lower()
            form_inputs = [inp.lower() for inp in form.get("inputs", [])]
            form_page = form.get("page", "/")

            # Check if this is a sensitive form
            is_sensitive = False
            form_type = ""

            for indicator in self.SENSITIVE_FORM_INDICATORS:
                if indicator in form_action or indicator in form_page.lower():
                    is_sensitive = True
                    form_type = indicator
                    break
                for inp in form_inputs:
                    if indicator in inp:
                        is_sensitive = True
                        form_type = indicator
                        break

            if not is_sensitive:
                continue

            # Check if CAPTCHA is present
            has_captcha = False
            page_url = self._build_url(base_url, form_page)
            page_response = self._make_request(page_url)

            if page_response:
                for pattern in captcha_patterns:
                    if re.search(pattern, page_response.text, re.IGNORECASE):
                        has_captcha = True
                        break

            if not has_captcha:
                yield Finding(
                    title=f"Missing CAPTCHA on {form_type.title()} Form",
                    severity=Severity.LOW,
                    description=f"Sensitive form ({form_type}) does not have CAPTCHA protection. "
                    "This could allow automated attacks.",
                    evidence=f"Page: {form_page}, Form action: {form_action}, "
                    f"No CAPTCHA patterns found",
                    remediation="Implement CAPTCHA (reCAPTCHA, hCaptcha, or similar) on "
                    "sensitive forms to prevent automated submissions.",
                    metadata={
                        "page": form_page,
                        "form_action": form_action,
                        "form_type": form_type,
                    },
                )

        self.set_progress(50)

    def _test_predictable_resources(self, target: str) -> Generator[Finding, None, None]:
        """Test for predictable resource locations and sequential IDs."""
        if not self._config.get("test_predictable", True):
            return

        base_url = self._normalize_url(target)

        # Test sequential ID patterns
        sequential_accessible = []

        for pattern in self.PREDICTABLE_PATTERNS:
            if self.is_cancelled():
                return

            test_url = self._build_url(base_url, pattern)
            response = self._make_request(test_url)

            if response and response.status_code == 200:
                sequential_accessible.append(pattern)

            time.sleep(self._delay_between_requests)

        if len(sequential_accessible) >= 2:
            # Check if we're seeing sequential access (e.g., /user/1 and
            # /user/2)
            paths_by_prefix = {}
            for path in sequential_accessible:
                prefix = "/".join(path.split("/")[:-1])
                if prefix not in paths_by_prefix:
                    paths_by_prefix[prefix] = []
                paths_by_prefix[prefix].append(path)

            for prefix, paths in paths_by_prefix.items():
                if len(paths) >= 2:
                    yield Finding(
                        title="Predictable Resource Identifiers",
                        severity=Severity.MEDIUM,
                        description=f"Resources under '{prefix}' use sequential/predictable IDs. "
                        "This may allow enumeration of resources.",
                        evidence=f"Accessible paths: {paths}",
                        remediation="Use UUIDs or other non-sequential identifiers for resources. "
                        "Implement proper authorization checks for resource access.",
                        metadata={"prefix": prefix, "accessible_paths": paths},
                    )

        self.set_progress(75)

    def _test_sensitive_files(self, target: str) -> Generator[Finding, None, None]:
        """Test for exposed sensitive files and directories."""
        base_url = self._normalize_url(target)

        total_files = len(self.SENSITIVE_FILES)

        for idx, file_path in enumerate(self.SENSITIVE_FILES):
            if self.is_cancelled():
                return

            test_url = self._build_url(base_url, file_path)
            response = self._make_request(test_url)

            if response and response.status_code == 200:
                # Verify it's actually the file and not a custom 404
                content_length = len(response.text)
                content_type = response.headers.get("content-type", "")

                # Skip if it looks like a custom error page
                if content_length < 50:
                    continue

                # Check for signs of actual file content
                is_actual_file = False

                if ".git" in file_path:
                    is_actual_file = "[core]" in response.text or "[remote" in response.text
                elif file_path.endswith(".env"):
                    is_actual_file = "=" in response.text and (
                        "KEY" in response.text.upper()
                        or "SECRET" in response.text.upper()
                        or "PASSWORD" in response.text.upper()
                    )
                elif file_path.endswith((".json", ".yml", ".yaml")):
                    is_actual_file = "{" in response.text or ":" in response.text
                elif file_path.endswith((".sql", ".bak")):
                    is_actual_file = (
                        "CREATE" in response.text.upper()
                        or "INSERT" in response.text.upper()
                        or "SELECT" in response.text.upper()
                    )
                elif file_path.endswith(".php"):
                    is_actual_file = "<?php" in response.text or "phpinfo" in response.text.lower()
                else:
                    # Generic check - if it has some content, consider it found
                    is_actual_file = content_length > 100

                if is_actual_file:
                    severity = (
                        Severity.HIGH
                        if any(
                            x in file_path
                            for x in [
                                ".env",
                                ".git",
                                "config",
                                "secret",
                                "password",
                                ".sql",
                                "backup",
                            ]
                        )
                        else Severity.MEDIUM
                    )

                    yield Finding(
                        title=f"Sensitive File Exposed: {file_path}",
                        severity=severity,
                        description=f"Sensitive file '{file_path}' is publicly accessible. "
                        "This may expose configuration, credentials, or source code.",
                        evidence=f"URL: {test_url}, Size: {content_length} bytes, "
                        f"Content-Type: {content_type}",
                        remediation="Remove sensitive files from web root. "
                        "Configure web server to deny access to sensitive files. "
                        "Use .htaccess or nginx configuration to block access.",
                        metadata={
                            "file": file_path,
                            "size": content_length,
                            "content_type": content_type,
                        },
                    )

            self.set_progress(75 + ((idx + 1) / total_files) * 25)
            time.sleep(self._delay_between_requests)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute insecure design attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Insecure Design Scan Started",
            severity=Severity.INFO,
            description="Starting scan for insecure design patterns",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Test 1: Rate Limiting (0-25%)
            yield from self._test_rate_limiting(target)

            # Test 2: CAPTCHA (25-50%)
            yield from self._test_captcha(target)

            # Test 3: Predictable Resources (50-75%)
            yield from self._test_predictable_resources(target)

            # Test 4: Sensitive Files (75-100%)
            yield from self._test_sensitive_files(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Insecure Design Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for insecure design patterns",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
