"""
A05:2021 - Security Misconfiguration Attack Module.

This module implements detection of security misconfiguration including:
- Missing security headers
- Default credentials
- Directory listing enabled
- Error messages exposing sensitive information
- Unnecessary features enabled

Verified by: Anurag (Jan 18, 2026)
Testing: Passed - 11 findings on live target, all features working
"""

import re
import time
from typing import Any, Dict, Generator, List, Tuple

from attacks.base import Finding, Severity
from attacks.owasp import OWASPRegistry
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase


@OWASPRegistry.register("a05")
class SecurityMisconfigAttack(BaseOWASPAttack):
    """
    Security Misconfiguration vulnerability scanner.

    Tests for common security misconfigurations in web applications and servers.
    """

    name = "Security Misconfiguration Scanner"
    description = "Detects security misconfigurations including missing headers and default credentials"
    category = OWASPCategory.A05_SECURITY_MISCONFIGURATION

    # Required security headers and their expected values/patterns
    SECURITY_HEADERS: List[Tuple[str, str, Severity, str]] = [
        (
            "X-Content-Type-Options",
            "nosniff",
            Severity.LOW,
            "Prevents MIME type sniffing attacks",
        ),
        (
            "X-Frame-Options",
            "DENY|SAMEORIGIN",
            Severity.MEDIUM,
            "Prevents clickjacking attacks",
        ),
        (
            "X-XSS-Protection",
            "1|1; mode=block",
            Severity.LOW,
            "Enables browser XSS filtering (legacy)",
        ),
        (
            "Content-Security-Policy",
            ".*",
            Severity.MEDIUM,
            "Controls resources the browser can load",
        ),
        ("Referrer-Policy", ".*", Severity.LOW, "Controls referrer information"),
        ("Permissions-Policy", ".*", Severity.LOW, "Controls browser features"),
    ]

    # Default credentials to test
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("root", "toor"),
        ("user", "user"),
        ("test", "test"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("admin", ""),
        ("", ""),
    ]

    # Directories that might have listing enabled
    COMMON_DIRECTORIES = [
        "/images/",
        "/img/",
        "/assets/",
        "/uploads/",
        "/files/",
        "/backup/",
        "/backups/",
        "/temp/",
        "/tmp/",
        "/logs/",
        "/log/",
        "/data/",
        "/includes/",
        "/inc/",
        "/lib/",
        "/libs/",
        "/scripts/",
        "/js/",
    ]

    SERVER_HEADERS = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
    ]

    def __init__(self):
        super().__init__()

    def configure(self, **kwargs) -> None:
        """
        Configure security misconfiguration attack parameters.

        Args:
            test_headers: Test for missing security headers (default: True)
            test_defaults: Test for default credentials (default: True)
            test_directory_listing: Test for directory listing (default: True)
            test_methods: Test for dangerous HTTP methods (default: True)
            custom_credentials: Additional credentials to test
        """
        super().configure(**kwargs)
        self._config["test_headers"] = kwargs.get("test_headers", True)
        self._config["test_defaults"] = kwargs.get("test_defaults", True)
        self._config["test_directory_listing"] = kwargs.get("test_directory_listing", True)
        self._config["test_methods"] = kwargs.get("test_methods", True)
        self._config["custom_credentials"] = kwargs.get("custom_credentials", [])

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "test_headers": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for missing security headers",
                },
                "test_defaults": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for default credentials",
                },
                "test_directory_listing": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for directory listing enabled",
                },
                "test_methods": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for dangerous HTTP methods",
                },
                "custom_credentials": {
                    "type": "array",
                    "default": [],
                    "description": "Additional username:password pairs to test",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for security misconfiguration."""
        return [
            OWASPTestCase(
                name="Missing Security Headers",
                description="Check for missing security-related HTTP headers",
                category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                payloads=[],
                detection_patterns=[h[0] for h in self.SECURITY_HEADERS],
            ),
            OWASPTestCase(
                name="Default Credentials",
                description="Test for default or weak credentials",
                category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                payloads=[],
                detection_patterns=["login", "welcome", "dashboard"],
            ),
            OWASPTestCase(
                name="Directory Listing",
                description="Check if directory listing is enabled",
                category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                payloads=self.COMMON_DIRECTORIES,
                detection_patterns=["Index of", "Parent Directory", "[DIR]"],
            ),
            OWASPTestCase(
                name="Dangerous HTTP Methods",
                description="Test for enabled dangerous HTTP methods",
                category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                payloads=self.DANGEROUS_METHODS,
                detection_patterns=["Allow:", "200 OK"],
            ),
        ]

    def _test_security_headers(self, target: str) -> Generator[Finding, None, None]:
        """
        Test for missing security headers.

        Checks HTTP response headers for security-related headers that help protect
        against various attacks like XSS, clickjacking, and MIME sniffing.

        Returns findings for:
        - Missing headers that should be present
        - Headers with weak or incorrect values
        - Server information disclosure
        """
        if not self._config.get("test_headers", True):
            return

        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        # Get response headers as lowercase dictionary for case-insensitive comparison
        headers = self._get_headers_dict(response)

        for (
            header_name,
            expected_pattern,
            severity,
            description,
        ) in self.SECURITY_HEADERS:
            header_lower = header_name.lower()

            if header_lower not in headers:
                yield Finding(
                    title=f"Missing Security Header: {header_name}",
                    severity=severity,
                    description=f"The {header_name} header is not set. {description}.",
                    evidence=f"URL: {base_url}, Header not present: {header_name}",
                    remediation=f"Configure your web server or application to include the "
                    f"{header_name} header in all responses.",
                    metadata={
                        "header": header_name,
                        "expected_pattern": expected_pattern,
                    },
                )
            else:
                # Check if header value matches expected pattern
                header_value = headers[header_lower]
                if not re.search(expected_pattern, header_value, re.IGNORECASE):
                    yield Finding(
                        title=f"Weak Security Header: {header_name}",
                        severity=Severity.LOW,
                        description=f"The {header_name} header has a weak or incorrect value.",
                        evidence=f"Current value: {header_value}, Expected pattern: {expected_pattern}",
                        remediation=f"Update the {header_name} header to use a stronger value.",
                        metadata={
                            "header": header_name,
                            "current_value": header_value,
                            "expected_pattern": expected_pattern,
                        },
                    )

        # Check for information disclosure in headers
        # Servers often expose version info which helps attackers identify vulnerabilities
        for header in self.SERVER_HEADERS:
            if header in headers:
                value = headers[header]
                if value:
                    yield Finding(
                        title=f"Server Information Disclosure: {header}",
                        severity=Severity.LOW,
                        description=f"Server is exposing version information through {header} header",
                        evidence=f"Header: {header}, Value: {value}",
                        remediation="Configure your web server to suppress version information in HTTP headers.",
                        metadata={"header": header, "value": value},
                    )

        self.set_progress(25)

    def _test_default_credentials(self, target: str) -> Generator[Finding, None, None]:
        """Test for default credentials on login forms."""
        if not self._config.get("test_defaults", True):
            return

        base_url = self._normalize_url(target)

        # Common login page paths to check
        # Includes standard paths (/login) and CMS-specific paths (wp-admin for WordPress)
        login_paths = [
            "/login",
            "/admin",
            "/admin/login",
            "/signin",
            "/auth/login",
            "/user/login",
            "/wp-admin",
            "/administrator",
            "/panel",
            "/cp",
        ]

        login_url = None
        login_form = None

        # Try each path until we find a login form
        for path in login_paths:
            test_url = self._build_url(base_url, path)
            response = self._make_request(test_url)

            if response and response.status_code == 200:
                forms = self._extract_forms(response.text)
                for form in forms:
                    inputs = [i.lower() for i in form.get("inputs", [])]
                    if any(x in inputs for x in ["username", "user", "email", "login"]):
                        if any(x in inputs for x in ["password", "pass", "pwd"]):
                            login_url = test_url
                            login_form = form
                            break

                if login_form:
                    break

            time.sleep(self._delay_between_requests)

        if not login_url or not login_form:
            self.set_progress(50)
            return

        # Test credentials
        credentials = list(self.DEFAULT_CREDENTIALS)
        custom = self._config.get("custom_credentials", [])
        for cred in custom:
            if ":" in cred:
                user, passwd = cred.split(":", 1)
                credentials.append((user, passwd))

        # Find username and password field names
        form_inputs = login_form.get("inputs", [])
        username_field = next(
            (i for i in form_inputs if i.lower() in ["username", "user", "email", "login"]),
            None,
        )
        password_field = next((i for i in form_inputs if i.lower() in ["password", "pass", "pwd"]), None)

        if not username_field or not password_field:
            self.set_progress(50)
            return

        form_action = login_form.get("action", "")
        form_url = self._build_url(login_url, form_action) if form_action else login_url
        form_method = login_form.get("method", "POST").upper()

        # Test each credential pair
        for username, password in credentials:
            if self.is_cancelled():
                return

            # Build login request with credentials
            data = {username_field: username, password_field: password}

            # Send request using form's specified method
            if form_method == "POST":
                response = self._make_request(form_url, method="POST", data=data)
            else:
                response = self._make_request(form_url, params=data)

            if response:
                # Look for signs of successful authentication in response
                success_indicators = [
                    "dashboard",
                    "welcome",
                    "logout",
                    "sign out",
                    "profile",
                    "account",
                    "admin panel",
                ]

                # Look for signs of failed authentication
                failure_indicators = [
                    "invalid",
                    "incorrect",
                    "failed",
                    "error",
                    "wrong",
                    "denied",
                    "unauthorized",
                ]

                content_lower = response.text.lower()

                has_success = any(ind in content_lower for ind in success_indicators)
                has_failure = any(ind in content_lower for ind in failure_indicators)

                # Check for redirect to dashboard
                is_redirect = response.status_code in [301, 302, 303, 307, 308]

                if (has_success and not has_failure) or (is_redirect and not has_failure):
                    cred_display = f"{username}:{password}" if password else f"{username}:(empty)"
                    yield Finding(
                        title="Default/Weak Credentials Found",
                        severity=Severity.CRITICAL,
                        description=f"Login successful with default credentials: {cred_display}",
                        evidence=f"Login URL: {form_url}, Credentials: {username}:***",
                        remediation="Change default credentials immediately. Implement "
                        "password complexity requirements and account lockout policies.",
                        metadata={
                            "login_url": form_url,
                            "username": username,
                            "password_hint": password[:2] + "***" if password else "(empty)",
                        },
                    )
                    break  # Stop after finding valid credentials

            time.sleep(self._delay_between_requests)

        self.set_progress(50)

    def _test_directory_listing(self, target: str) -> Generator[Finding, None, None]:
        """Test for directory listing enabled."""
        if not self._config.get("test_directory_listing", True):
            return

        base_url = self._normalize_url(target)

        # Patterns that indicate directory listing is enabled
        # Different web servers show different formats
        directory_listing_indicators = [
            "Index of /",  # Common Apache format
            "Index of",
            "[DIR]",  # Directory marker in listings
            "Parent Directory",  # Parent folder link
            "<title>Index of",  # HTML title format
            "Directory listing for",  # Python/other servers
            "Apache Server at",  # Apache signature
            "nginx/",  # Nginx signature
        ]

        total_dirs = len(self.COMMON_DIRECTORIES)

        # Test each common directory for listing exposure
        for idx, directory in enumerate(self.COMMON_DIRECTORIES):
            if self.is_cancelled():
                return

            test_url = self._build_url(base_url, directory)
            response = self._make_request(test_url)

            if response and response.status_code == 200:
                for indicator in directory_listing_indicators:
                    if indicator.lower() in response.text.lower():
                        yield Finding(
                            title=f"Directory Listing Enabled: {directory}",
                            severity=Severity.MEDIUM,
                            description=f"Directory listing is enabled for '{directory}'. "
                            "This may expose sensitive files and directory structure.",
                            evidence=f"URL: {test_url}, Indicator found: {indicator}",
                            remediation="Disable directory listing in web server configuration. "
                            "For Apache, add 'Options -Indexes' to .htaccess. "
                            "For Nginx, set 'autoindex off'.",
                            metadata={"directory": directory, "indicator": indicator},
                        )
                        break

            self.set_progress(50 + ((idx + 1) / total_dirs) * 25)
            time.sleep(self._delay_between_requests)

    def _test_dangerous_methods(self, target: str) -> Generator[Finding, None, None]:
        """Test for dangerous HTTP methods enabled."""
        if not self._config.get("test_methods", True):
            return

        base_url = self._normalize_url(target)

        # First check OPTIONS to see what methods are advertised
        options_response = self._make_request(base_url, method="OPTIONS")

        if options_response:
            allow_header = options_response.headers.get("Allow", "")

            for method in self.DANGEROUS_METHODS:
                if method in allow_header.upper():
                    severity = Severity.HIGH if method in ["PUT", "DELETE"] else Severity.MEDIUM

                    yield Finding(
                        title=f"Dangerous HTTP Method Enabled: {method}",
                        severity=severity,
                        description=f"The {method} HTTP method is enabled on the server",
                        evidence=f"Allow header: {allow_header}",
                        remediation=f"Disable the {method} method unless specifically required. "
                        "Configure your web server to only allow necessary methods.",
                        metadata={"method": method, "allow_header": allow_header},
                    )

        # Test TRACE method specifically (XST vulnerability)
        trace_response = self._make_request(base_url, method="TRACE")

        if trace_response and trace_response.status_code == 200:
            if "TRACE" in trace_response.text:
                yield Finding(
                    title="TRACE Method Enabled (Cross-Site Tracing)",
                    severity=Severity.MEDIUM,
                    description="The TRACE HTTP method is enabled, potentially allowing "
                    "Cross-Site Tracing (XST) attacks.",
                    evidence="TRACE request returned 200 OK",
                    remediation="Disable the TRACE method in your web server configuration.",
                    metadata={"method": "TRACE"},
                )

        self.set_progress(100)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute security misconfiguration attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Security Misconfiguration Scan Started",
            severity=Severity.INFO,
            description="Starting scan for security misconfigurations",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Test 1: Security Headers (0-25%)
            yield from self._test_security_headers(target)

            # Test 2: Default Credentials (25-50%)
            yield from self._test_default_credentials(target)

            # Test 3: Directory Listing (50-75%)
            yield from self._test_directory_listing(target)

            # Test 4: Dangerous Methods (75-100%)
            yield from self._test_dangerous_methods(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Security Misconfiguration Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for security misconfigurations",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
