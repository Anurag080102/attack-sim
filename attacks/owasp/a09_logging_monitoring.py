"""
A09:2021 - Security Logging and Monitoring Failures Attack Module.

This module implements detection of logging and monitoring vulnerabilities including:
- Error message information disclosure
- Debug mode detection
- Stack trace exposure
- Verbose error pages
- Missing security logging indicators
"""

import re
import time
from typing import Generator, Dict, Any, List
# urljoin removed - not currently used

from attacks.base import Finding, Severity
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase
from attacks.owasp import OWASPRegistry


@OWASPRegistry.register("a09")
class LoggingMonitoringAttack(BaseOWASPAttack):
    """
    Security Logging and Monitoring Failures scanner.

    Tests for information disclosure through error messages and debug endpoints.
    """

    name = "Logging and Monitoring Failures Scanner"
    description = "Detects information disclosure and debug mode issues"
    category = OWASPCategory.A09_LOGGING_MONITORING

    # URLs that trigger errors
    ERROR_TRIGGER_URLS = [
        "/nonexistent_page_12345",
        "/error",
        "/test'",
        "/test<>",
        "/test%00",
        "/?id=",
        "/?id='",
        "/?id=<script>",
        "/null",
        "/%00",
        "/../../../etc/passwd",
    ]

    # Debug/development endpoints
    DEBUG_ENDPOINTS = [
        "/debug",
        "/debug/",
        "/_debug",
        "/console",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/debug.php",
        "/__debug__",
        "/trace",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/mappings",
        "/api/debug",
        "/api/test",
        "/.env",
        "/config",
        "/elmah.axd",
        "/errorlog.axd",
        "/trace.axd",
    ]

    # Patterns indicating debug/development mode
    DEBUG_PATTERNS = [
        r'DEBUG\s*=\s*True',
        r'debug\s*mode',
        r'development\s*mode',
        r'FLASK_DEBUG',
        r'DJANGO_DEBUG',
        r'APP_DEBUG',
        r'WP_DEBUG',
        r'display_errors\s*=\s*On',
        r'error_reporting\s*=\s*E_ALL',
    ]

    # Stack trace patterns by language
    STACK_TRACE_PATTERNS = {
        "python": [
            r'Traceback \(most recent call last\)',
            r'File "[^"]+", line \d+',
            r'raise \w+Error',
            r'\.py", line \d+',
        ],
        "java": [
            r'at \w+\.\w+\(\w+\.java:\d+\)',
            r'java\.\w+\.\w+Exception',
            r'\.java:\d+\)',
            r'Caused by:',
        ],
        "php": [
            r'Fatal error:',
            r'Parse error:',
            r'Warning:.*in .* on line',
            r'Stack trace:',
            r'#\d+ .+\.php\(\d+\)',
        ],
        "dotnet": [
            r'System\.\w+Exception',
            r'at \w+\.\w+\.\w+\(',
            r'\.cs:line \d+',
            r'Stack Trace:',
            r'Server Error in',
        ],
        "javascript": [
            r'at \w+\s+\([^)]+:\d+:\d+\)',
            r'TypeError:',
            r'ReferenceError:',
            r'SyntaxError:',
            r'Error:.*\n\s+at',
        ],
        "ruby": [
            r'\.rb:\d+:in',
            r'NoMethodError',
            r'NameError',
            r'ActionController::',
        ],
    }

    # Sensitive information patterns in error messages
    SENSITIVE_INFO_PATTERNS = [
        (r'/[a-zA-Z]:/[^\s<>"]+', "File path disclosure"),
        (r'/(?:home|var|usr|opt|etc)/[^\s<>"]+', "Unix path disclosure"),
        (r'(?:mysql|postgres|oracle|mongodb)://[^\s<>"]+', "Database connection string"),
        (r'password["\']?\s*[:=]\s*["\'][^"\']+["\']', "Password in error"),
        (r'(?:api[_-]?key|secret|token)["\']?\s*[:=]\s*["\'][^"\']+["\']', "API key/secret exposure"),
        (r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', "Email address"),
        (r'(?:version|v)\s*[:=]?\s*[\d.]+', "Version disclosure"),
        (r'(?:server|apache|nginx|iis|php|python|ruby|node)[/\s]*[\d.]+', "Software version"),
    ]

    def __init__(self):
        super().__init__()

    def configure(self, **kwargs) -> None:
        """
        Configure logging/monitoring failures attack parameters.

        Args:
            test_errors: Test error handling disclosure (default: True)
            test_debug: Test for debug endpoints (default: True)
            test_stack_traces: Test for stack trace exposure (default: True)
        """
        super().configure(**kwargs)
        self._config["test_errors"] = kwargs.get("test_errors", True)
        self._config["test_debug"] = kwargs.get("test_debug", True)
        self._config["test_stack_traces"] = kwargs.get("test_stack_traces", True)

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update({
            "test_errors": {
                "type": "boolean",
                "default": True,
                "description": "Test error handling for information disclosure"
            },
            "test_debug": {
                "type": "boolean",
                "default": True,
                "description": "Test for debug endpoints and modes"
            },
            "test_stack_traces": {
                "type": "boolean",
                "default": True,
                "description": "Test for stack trace exposure"
            }
        })
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for logging/monitoring failures."""
        return [
            OWASPTestCase(
                name="Error Message Disclosure",
                description="Test for verbose error messages",
                category=OWASPCategory.A09_LOGGING_MONITORING,
                payloads=self.ERROR_TRIGGER_URLS,
                detection_patterns=["error", "exception", "traceback"]
            ),
            OWASPTestCase(
                name="Debug Endpoints",
                description="Check for accessible debug endpoints",
                category=OWASPCategory.A09_LOGGING_MONITORING,
                payloads=self.DEBUG_ENDPOINTS,
                detection_patterns=self.DEBUG_PATTERNS
            ),
            OWASPTestCase(
                name="Stack Trace Exposure",
                description="Detect exposed stack traces",
                category=OWASPCategory.A09_LOGGING_MONITORING,
                payloads=[],
                detection_patterns=list(self.STACK_TRACE_PATTERNS.keys())
            )
        ]

    def _test_error_disclosure(self, target: str) -> Generator[Finding, None, None]:
        """Test for information disclosure in error responses."""
        if not self._config.get("test_errors", True):
            return

        base_url = self._normalize_url(target)
        total_urls = len(self.ERROR_TRIGGER_URLS)

        for idx, error_url in enumerate(self.ERROR_TRIGGER_URLS):
            if self.is_cancelled():
                return

            test_url = self._build_url(base_url, error_url)
            response = self._make_request(test_url)

            if response:
                content = response.text

                # Check for stack traces
                for lang, patterns in self.STACK_TRACE_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                            yield Finding(
                                title=f"Stack Trace Exposed ({lang})",
                                severity=Severity.MEDIUM,
                                description=f"Error response contains {lang} stack trace, "
                                           "potentially exposing internal code structure.",
                                evidence=f"URL: {test_url}, Pattern: {pattern[:50]}",
                                remediation="Configure custom error pages that don't expose "
                                           "stack traces. Log detailed errors server-side only.",
                                metadata={
                                    "url": test_url,
                                    "language": lang,
                                    "pattern": pattern
                                }
                            )
                            break

                # Check for sensitive information
                for pattern, description in self.SENSITIVE_INFO_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Deduplicate and limit matches
                        unique_matches = list(set(matches))[:3]

                        yield Finding(
                            title=f"Information Disclosure: {description}",
                            severity=Severity.MEDIUM,
                            description=f"Error response contains {description.lower()}",
                            evidence=f"URL: {test_url}, Found: {unique_matches}",
                            remediation="Sanitize error messages. Remove paths, versions, "
                                       "and other sensitive information from user-facing errors.",
                            metadata={
                                "url": test_url,
                                "type": description,
                                "matches": unique_matches
                            }
                        )

            self.set_progress((idx + 1) / total_urls * 33)
            time.sleep(self._delay_between_requests)

    def _test_debug_endpoints(self, target: str) -> Generator[Finding, None, None]:
        """Test for accessible debug endpoints."""
        if not self._config.get("test_debug", True):
            return

        base_url = self._normalize_url(target)
        total_endpoints = len(self.DEBUG_ENDPOINTS)

        for idx, endpoint in enumerate(self.DEBUG_ENDPOINTS):
            if self.is_cancelled():
                return

            test_url = self._build_url(base_url, endpoint)
            response = self._make_request(test_url)

            if response and response.status_code == 200:
                content = response.text.lower()
                content_length = len(response.text)

                # Check for actual debug content (not just a redirect or error page)
                debug_indicators = [
                    "debug", "configuration", "environment", "settings",
                    "variables", "phpinfo", "server info", "system",
                    "actuator", "beans", "mappings", "health"
                ]

                found_indicators = [i for i in debug_indicators if i in content]

                if found_indicators and content_length > 200:
                    severity = Severity.HIGH

                    # Extra high severity for certain endpoints
                    if any(x in endpoint for x in [".env", "phpinfo", "actuator/env", "config"]):
                        severity = Severity.CRITICAL

                    yield Finding(
                        title=f"Debug Endpoint Accessible: {endpoint}",
                        severity=severity,
                        description=f"Debug/development endpoint is publicly accessible. "
                                   f"Found indicators: {found_indicators}",
                        evidence=f"URL: {test_url}, Status: 200, Size: {content_length} bytes",
                        remediation="Disable debug endpoints in production. "
                                   "Restrict access via authentication or IP allowlisting.",
                        metadata={
                            "endpoint": endpoint,
                            "indicators": found_indicators,
                            "size": content_length
                        }
                    )

            self.set_progress(33 + (idx + 1) / total_endpoints * 33)
            time.sleep(self._delay_between_requests)

    def _test_debug_mode_detection(self, target: str) -> Generator[Finding, None, None]:
        """Detect debug mode through response analysis."""
        if not self._config.get("test_stack_traces", True):
            return

        base_url = self._normalize_url(target)

        # Get the main page
        response = self._make_request(base_url)

        if not response:
            return

        content = response.text
        headers = self._get_headers_dict(response)

        # Check for debug mode indicators in response
        for pattern in self.DEBUG_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                yield Finding(
                    title="Debug Mode Detected",
                    severity=Severity.HIGH,
                    description="Application appears to be running in debug mode",
                    evidence=f"Pattern matched: {pattern}",
                    remediation="Disable debug mode in production. Set DEBUG=False "
                               "and ensure production configurations are used.",
                    metadata={"pattern": pattern}
                )

        # Check for debug-related headers
        debug_headers = {
            "x-debug-token": "Debug token header (Symfony)",
            "x-debug-token-link": "Debug profiler link",
            "x-powered-by": "Server technology disclosure",
        }

        for header, description in debug_headers.items():
            if header in headers:
                severity = Severity.LOW
                if "debug" in header:
                    severity = Severity.MEDIUM

                yield Finding(
                    title=f"Debug Header Present: {header}",
                    severity=severity,
                    description=f"{description} found in response headers",
                    evidence=f"Header: {header}: {headers[header]}",
                    remediation="Remove debug headers in production. "
                               "Configure web server to strip sensitive headers.",
                    metadata={
                        "header": header,
                        "value": headers[header]
                    }
                )

        # Check for verbose server errors (custom test)
        error_urls = [
            f"{base_url}/generate_error",
            f"{base_url}/?error=1",
            f"{base_url}/?debug=1",
        ]

        for url in error_urls:
            response = self._make_request(url)

            if response:
                content = response.text

                # Check for detailed error output
                verbose_error_patterns = [
                    r'Settings\.py',
                    r'urls\.py',
                    r'views\.py',
                    r'models\.py',
                    r'web\.config',
                    r'applicationhost\.config',
                    r'httpd\.conf',
                    r'nginx\.conf',
                ]

                for pattern in verbose_error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        yield Finding(
                            title="Configuration File Reference Exposed",
                            severity=Severity.MEDIUM,
                            description="Error response references configuration files",
                            evidence=f"URL: {url}, Pattern: {pattern}",
                            remediation="Configure custom error pages without file references",
                            metadata={"url": url, "pattern": pattern}
                        )
                        break

            time.sleep(self._delay_between_requests)

        self.set_progress(100)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute logging/monitoring failures attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Logging/Monitoring Failures Scan Started",
            severity=Severity.INFO,
            description="Starting scan for logging and monitoring failures",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target}
        )

        try:
            # Test 1: Error Disclosure (0-33%)
            yield from self._test_error_disclosure(target)

            # Test 2: Debug Endpoints (33-66%)
            yield from self._test_debug_endpoints(target)

            # Test 3: Debug Mode Detection (66-100%)
            yield from self._test_debug_mode_detection(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Logging/Monitoring Failures Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for logging and monitoring failures",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target}
        )
