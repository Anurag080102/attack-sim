"""
A07:2021 - Identification and Authentication Failures Attack Module.

This module implements detection of authentication vulnerabilities including:
- Weak password policies
- Session management issues
- Missing brute force protection
- Credential stuffing vulnerabilities
- Insecure password recovery
"""

import hashlib
import re
import time
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import urljoin, urlparse

from attacks.base import Finding, Severity
from attacks.owasp import OWASPRegistry
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase


@OWASPRegistry.register("a07")
class AuthFailuresAttack(BaseOWASPAttack):
    """
    Identification and Authentication Failures scanner.

    Tests for weak authentication mechanisms and session management issues.
    """

    name = "Authentication Failures Scanner"
    description = "Detects authentication and session management vulnerabilities"
    category = OWASPCategory.A07_AUTH_FAILURES

    # Weak passwords to test for password policy
    WEAK_PASSWORDS = [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "abc123",
        "111111",
        "123123",
        "admin",
        "letmein",
        "welcome",
        "1234",
        "test",
        "a",
        "aa",
        "aaa",
    ]

    # Common username enumeration test accounts
    TEST_USERNAMES = [
        "admin",
        "administrator",
        "root",
        "user",
        "test",
        "guest",
        "info",
        "mysql",
        "postgres",
    ]

    # Session cookie attributes to check
    COOKIE_SECURITY_ATTRS = [
        ("httponly", "HttpOnly flag prevents JavaScript access to cookies"),
        ("secure", "Secure flag ensures cookies only sent over HTTPS"),
        ("samesite", "SameSite attribute protects against CSRF"),
    ]

    def __init__(self):
        super().__init__()
        self._session_tokens: List[str] = []

    def configure(self, **kwargs) -> None:
        """
        Configure authentication failures attack parameters.

        Args:
            test_password_policy: Test for weak password policies (default: True)
            test_enumeration: Test for username enumeration (default: True)
            test_session: Test session management (default: True)
            test_lockout: Test for account lockout (default: True)
        """
        super().configure(**kwargs)
        self._config["test_password_policy"] = kwargs.get("test_password_policy", True)
        self._config["test_enumeration"] = kwargs.get("test_enumeration", True)
        self._config["test_session"] = kwargs.get("test_session", True)
        self._config["test_lockout"] = kwargs.get("test_lockout", True)

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "test_password_policy": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for weak password policies",
                },
                "test_enumeration": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for username enumeration",
                },
                "test_session": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test session management security",
                },
                "test_lockout": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for account lockout mechanism",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for authentication failures."""
        return [
            OWASPTestCase(
                name="Password Policy",
                description="Test for weak password policy enforcement",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=self.WEAK_PASSWORDS,
                detection_patterns=["password", "weak", "strength"],
            ),
            OWASPTestCase(
                name="Username Enumeration",
                description="Test for username enumeration via error messages",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=self.TEST_USERNAMES,
                detection_patterns=["not found", "doesn't exist", "invalid user"],
            ),
            OWASPTestCase(
                name="Session Management",
                description="Test session token security",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=[],
                detection_patterns=["session", "cookie", "token"],
            ),
            OWASPTestCase(
                name="Account Lockout",
                description="Test for missing account lockout policy",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=[],
                detection_patterns=["locked", "too many attempts", "try again"],
            ),
        ]

    def _find_auth_endpoints(self, target: str) -> Dict[str, Optional[str]]:
        """Find authentication-related endpoints."""
        base_url = self._normalize_url(target)

        endpoints: Dict[str, Optional[str]] = {
            "login": None,
            "register": None,
            "forgot_password": None,
            "reset_password": None,
            "logout": None,
        }

        # Common paths for each endpoint type
        login_paths = [
            "/login",
            "/signin",
            "/auth/login",
            "/user/login",
            "/account/login",
        ]
        register_paths = [
            "/register",
            "/signup",
            "/auth/register",
            "/user/register",
            "/create-account",
        ]
        forgot_paths = [
            "/forgot-password",
            "/password/forgot",
            "/auth/forgot",
            "/reset",
            "/recover",
        ]

        for path in login_paths:
            url = self._build_url(base_url, path)
            response = self._make_request(url)
            if response and response.status_code == 200:
                endpoints["login"] = url
                break
            time.sleep(self._delay_between_requests)

        for path in register_paths:
            url = self._build_url(base_url, path)
            response = self._make_request(url)
            if response and response.status_code == 200:
                endpoints["register"] = url
                break
            time.sleep(self._delay_between_requests)

        for path in forgot_paths:
            url = self._build_url(base_url, path)
            response = self._make_request(url)
            if response and response.status_code == 200:
                endpoints["forgot_password"] = url
                break
            time.sleep(self._delay_between_requests)

        return endpoints

    def _test_username_enumeration(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Test for username enumeration via different error messages."""
        if not self._config.get("test_enumeration", True):
            return

        login_url = endpoints.get("login")
        if not login_url:
            return

        # Get the login form
        response = self._make_request(login_url)
        if not response:
            return

        forms = self._extract_forms(response.text)
        if not forms:
            return

        # Find the login form
        login_form = None
        for form in forms:
            inputs = [i.lower() for i in form.get("inputs", [])]
            if any(x in inputs for x in ["username", "user", "email", "login"]):
                login_form = form
                break

        if not login_form:
            return

        form_inputs = login_form.get("inputs", [])
        username_field = next(
            (
                i
                for i in form_inputs
                if i.lower() in ["username", "user", "email", "login"]
            ),
            None,
        )
        password_field = next(
            (i for i in form_inputs if i.lower() in ["password", "pass", "pwd"]), None
        )

        if not username_field or not password_field:
            return

        form_action = login_form.get("action", "")
        form_url = urljoin(login_url, form_action) if form_action else login_url

        # Test with known-invalid username and known-valid-looking username
        responses = {}

        test_cases = [
            ("definitely_not_a_real_user_12345", "wrongpassword"),
            ("admin", "wrongpassword"),
            ("user", "wrongpassword"),
        ]

        for username, password in test_cases:
            if self.is_cancelled():
                return

            data = {username_field: username, password_field: password}
            response = self._make_request(form_url, method="POST", data=data)

            if response:
                responses[username] = {
                    "status": response.status_code,
                    "length": len(response.text),
                    "text": response.text[:500],
                }

            time.sleep(self._delay_between_requests)

        # Analyze responses for enumeration
        if len(responses) >= 2:
            lengths = [r["length"] for r in responses.values()]
            texts = [r["text"] for r in responses.values()]

            # Check if responses differ significantly
            length_diff = max(lengths) - min(lengths)

            # Check for different error messages
            error_patterns = [
                (r"user.*not.*found", "User not found message"),
                (r"invalid.*user", "Invalid user message"),
                (r"no.*account", "No account message"),
                (r"doesn't.*exist", "Account doesn't exist message"),
                (r"unknown.*user", "Unknown user message"),
            ]

            for text in texts:
                for pattern, description in error_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        yield Finding(
                            title="Username Enumeration Possible",
                            severity=Severity.MEDIUM,
                            description="The application reveals whether a username exists through "
                            "distinct error messages.",
                            evidence=f"Pattern found: {description}",
                            remediation="Use generic error messages like 'Invalid username or password' "
                            "for all login failures.",
                            metadata={"pattern": pattern, "description": description},
                        )
                        break

            if length_diff > 50:
                yield Finding(
                    title="Username Enumeration via Response Length",
                    severity=Severity.MEDIUM,
                    description="Login responses have different lengths for valid vs invalid usernames, "
                    "potentially allowing username enumeration.",
                    evidence=f"Response length difference: {length_diff} bytes",
                    remediation="Ensure login failure responses are identical regardless of "
                    "whether the username exists.",
                    metadata={"length_difference": length_diff},
                )

        self.set_progress(25)

    def _test_password_policy(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Test for weak password policy on registration."""
        if not self._config.get("test_password_policy", True):
            return

        register_url = endpoints.get("register")
        if not register_url:
            self.set_progress(50)
            return

        response = self._make_request(register_url)
        if not response:
            return

        forms = self._extract_forms(response.text)
        if not forms:
            return

        # Find registration form
        reg_form = None
        for form in forms:
            inputs = [i.lower() for i in form.get("inputs", [])]
            if any(x in inputs for x in ["password", "pass", "pwd"]):
                if any(x in inputs for x in ["email", "username", "user"]):
                    reg_form = form
                    break

        if not reg_form:
            return

        form_inputs = reg_form.get("inputs", [])
        email_field = next(
            (i for i in form_inputs if i.lower() in ["email", "username", "user"]), None
        )
        password_field = next(
            (i for i in form_inputs if i.lower() in ["password", "pass", "pwd"]), None
        )

        if not email_field or not password_field:
            return

        form_action = reg_form.get("action", "")
        form_url = urljoin(register_url, form_action) if form_action else register_url

        # Test weak passwords
        weak_passwords_accepted = []

        for weak_pwd in self.WEAK_PASSWORDS[:5]:  # Test first 5
            if self.is_cancelled():
                return

            # Generate unique test email
            test_email = (
                f"test_{hashlib.md5(weak_pwd.encode()).hexdigest()[:8]}@test.invalid"
            )

            data = {email_field: test_email, password_field: weak_pwd}

            # Add confirm password if present
            confirm_field = next(
                (
                    i
                    for i in form_inputs
                    if "confirm" in i.lower() or "repeat" in i.lower()
                ),
                None,
            )
            if confirm_field:
                data[confirm_field] = weak_pwd

            response = self._make_request(form_url, method="POST", data=data)

            if response:
                content_lower = response.text.lower()

                # Check if password was accepted (no password error message)
                password_rejected_patterns = [
                    "password.*weak",
                    "password.*short",
                    "password.*simple",
                    "password.*must",
                    "password.*require",
                    "stronger.*password",
                    "password.*length",
                    "password.*character",
                ]

                was_rejected = any(
                    re.search(p, content_lower) for p in password_rejected_patterns
                )

                if not was_rejected:
                    # Check for success indicators
                    success_patterns = [
                        "success",
                        "created",
                        "registered",
                        "welcome",
                        "verify",
                    ]
                    if any(p in content_lower for p in success_patterns):
                        weak_passwords_accepted.append(weak_pwd)

            time.sleep(self._delay_between_requests)

        if weak_passwords_accepted:
            yield Finding(
                title="Weak Password Policy",
                severity=Severity.HIGH,
                description="The application accepts weak passwords during registration",
                evidence=f"Weak passwords accepted: {weak_passwords_accepted}",
                remediation="Implement strong password requirements: minimum 8 characters, "
                "mix of uppercase, lowercase, numbers, and special characters. "
                "Consider using password strength meters and checking against "
                "breached password databases.",
                metadata={"weak_passwords": weak_passwords_accepted},
            )

        self.set_progress(50)

    def _test_session_security(self, target: str) -> Generator[Finding, None, None]:
        """Test session management security."""
        if not self._config.get("test_session", True):
            return

        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        # Check cookies
        cookies = response.cookies
        set_cookie_header = response.headers.get("Set-Cookie", "")

        if cookies or set_cookie_header:
            # Check for session cookies
            session_cookie_names = [
                "session",
                "sessionid",
                "sess",
                "sid",
                "phpsessid",
                "jsessionid",
                "asp.net_sessionid",
            ]

            for cookie in cookies:
                cookie_name_lower = cookie.name.lower()
                cookie_value = cookie.value or ""

                is_session_cookie = any(
                    s in cookie_name_lower for s in session_cookie_names
                )

                if (
                    is_session_cookie or len(cookie_value) > 20
                ):  # Likely a session token
                    # Check cookie security attributes
                    cookie_str = set_cookie_header.lower()

                    if "httponly" not in cookie_str:
                        yield Finding(
                            title="Session Cookie Missing HttpOnly Flag",
                            severity=Severity.MEDIUM,
                            description=f"Cookie '{cookie.name}' is missing the HttpOnly flag, "
                            "making it accessible via JavaScript",
                            evidence=f"Cookie: {cookie.name}",
                            remediation="Set the HttpOnly flag on all session cookies to prevent "
                            "JavaScript access.",
                            metadata={"cookie_name": cookie.name},
                        )

                    if "secure" not in cookie_str:
                        parsed = urlparse(base_url)
                        if parsed.scheme == "https":
                            yield Finding(
                                title="Session Cookie Missing Secure Flag",
                                severity=Severity.MEDIUM,
                                description=f"Cookie '{cookie.name}' is missing the Secure flag on HTTPS site",
                                evidence=f"Cookie: {cookie.name}",
                                remediation="Set the Secure flag on all session cookies to ensure "
                                "they're only sent over HTTPS.",
                                metadata={"cookie_name": cookie.name},
                            )

                    if "samesite" not in cookie_str:
                        yield Finding(
                            title="Session Cookie Missing SameSite Attribute",
                            severity=Severity.LOW,
                            description=f"Cookie '{cookie.name}' is missing the SameSite attribute",
                            evidence=f"Cookie: {cookie.name}",
                            remediation="Set SameSite=Strict or SameSite=Lax on session cookies "
                            "to protect against CSRF attacks.",
                            metadata={"cookie_name": cookie.name},
                        )

                    # Check session token entropy
                    if len(cookie_value) < 16:
                        yield Finding(
                            title="Short Session Token",
                            severity=Severity.HIGH,
                            description=f"Session token '{cookie.name}' appears to have low entropy "
                            f"(length: {len(cookie_value)})",
                            evidence=f"Token length: {len(cookie_value)} characters",
                            remediation="Use cryptographically secure random session tokens "
                            "with at least 128 bits of entropy.",
                            metadata={
                                "cookie_name": cookie.name,
                                "token_length": len(cookie_value),
                            },
                        )

        self.set_progress(75)

    def _test_account_lockout(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Test for account lockout mechanism."""
        if not self._config.get("test_lockout", True):
            return

        login_url = endpoints.get("login")
        if not login_url:
            return

        response = self._make_request(login_url)
        if not response:
            return

        forms = self._extract_forms(response.text)
        if not forms:
            return

        login_form = None
        for form in forms:
            inputs = [i.lower() for i in form.get("inputs", [])]
            if any(x in inputs for x in ["username", "user", "email"]):
                login_form = form
                break

        if not login_form:
            return

        form_inputs = login_form.get("inputs", [])
        username_field = next(
            (
                i
                for i in form_inputs
                if i.lower() in ["username", "user", "email", "login"]
            ),
            None,
        )
        password_field = next(
            (i for i in form_inputs if i.lower() in ["password", "pass", "pwd"]), None
        )

        if not username_field or not password_field:
            return

        form_action = login_form.get("action", "")
        form_url = urljoin(login_url, form_action) if form_action else login_url

        # Try multiple failed logins
        test_username = "admin"
        lockout_detected = False
        attempts = 0
        max_attempts = 10

        for i in range(max_attempts):
            if self.is_cancelled():
                return

            data = {username_field: test_username, password_field: f"wrongpassword{i}"}

            response = self._make_request(form_url, method="POST", data=data)
            attempts += 1

            if response:
                content_lower = response.text.lower()

                lockout_patterns = [
                    "locked",
                    "too many",
                    "try again later",
                    "temporarily",
                    "blocked",
                    "exceeded",
                    "wait",
                    "minute",
                    "captcha",
                ]

                if any(p in content_lower for p in lockout_patterns):
                    lockout_detected = True
                    break

                if response.status_code == 429:
                    lockout_detected = True
                    break

            time.sleep(0.1)  # Quick attempts to trigger lockout

        if not lockout_detected:
            yield Finding(
                title="No Account Lockout Detected",
                severity=Severity.HIGH,
                description=f"No account lockout after {attempts} failed login attempts. "
                "This makes the application vulnerable to brute force attacks.",
                evidence=f"Attempted {attempts} failed logins without lockout",
                remediation="Implement account lockout after 3-5 failed attempts. "
                "Consider using progressive delays, CAPTCHA, or temporary account locks.",
                metadata={"attempts": attempts},
            )
        else:
            yield Finding(
                title="Account Lockout Mechanism Present",
                severity=Severity.INFO,
                description=f"Account lockout detected after {attempts} attempts",
                evidence=f"Lockout triggered after {attempts} failed attempts",
                remediation="N/A - Security control is in place",
                metadata={"attempts_to_lockout": attempts},
            )

        self.set_progress(100)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute authentication failures attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Authentication Failures Scan Started",
            severity=Severity.INFO,
            description="Starting scan for authentication vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Find authentication endpoints
            endpoints = self._find_auth_endpoints(target)

            yield Finding(
                title="Authentication Endpoints Discovery",
                severity=Severity.INFO,
                description="Discovered authentication endpoints",
                evidence=f"Endpoints: {endpoints}",
                remediation="N/A - Informational",
                metadata={"endpoints": endpoints},
            )

            # Test 1: Username Enumeration (0-25%)
            yield from self._test_username_enumeration(target, endpoints)

            # Test 2: Password Policy (25-50%)
            yield from self._test_password_policy(target, endpoints)

            # Test 3: Session Security (50-75%)
            yield from self._test_session_security(target)

            # Test 4: Account Lockout (75-100%)
            yield from self._test_account_lockout(target, endpoints)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Authentication Failures Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for authentication vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
