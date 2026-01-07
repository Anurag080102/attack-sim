"""
A07:2025 - Authentication Failures Attack Module.

This module provides a comprehensive security scanner for detecting authentication
and session management vulnerabilities as defined in OWASP Top 10:2025 A07.

Overview
--------
Authentication failures remain one of the most critical web application security
risks. This scanner identifies weaknesses that could allow attackers to compromise
passwords, keys, session tokens, or exploit implementation flaws to assume other
users' identities.

Features
--------
The scanner implements the following security tests:

1. **Endpoint Discovery**
   - Smart crawling with keyword-based scoring
   - Detection of login, registration, password reset, and OAuth endpoints
   - Form extraction with field type identification

2. **Username Enumeration**
   - Response-based detection (status codes, content length, error messages)
   - Timing-based detection using statistical analysis
   - Password reset flow enumeration

3. **Credential Testing**
   - Default credential pair testing (admin:admin, root:root, etc.)
   - Weak password policy detection
   - Common password acceptance testing

4. **Session Management**
   - Cookie security attributes (HttpOnly, Secure, SameSite)
   - Session token entropy analysis
   - Session fixation vulnerability detection
   - Sequential/predictable token detection

5. **JWT Security**
   - Algorithm validation (none, weak symmetric)
   - Expiration claim verification
   - Sensitive data exposure in payload
   - Audience/issuer claim presence

6. **Brute Force Protection**
   - Account lockout mechanism detection
   - Rate limiting header analysis
   - CAPTCHA presence detection

7. **Multi-Factor Authentication**
   - MFA presence detection
   - Configuration assessment

8. **Password Reset Security**
   - User enumeration via reset flow
   - Host header injection testing

Usage
-----
    from attacks.owasp.a07_auth_failures import AuthFailuresAttack

    scanner = AuthFailuresAttack()
    scanner.configure(timeout=10, verify_ssl=True)

    for finding in scanner.run("https://target.com"):
        print(f"[{finding.severity}] {finding.title}")

Configuration Options
--------------------
- test_enumeration: Enable username enumeration tests (default: True)
- test_default_credentials: Test common credential pairs (default: True)
- test_password_policy: Test password strength requirements (default: True)
- test_session: Test session management security (default: True)
- test_session_fixation: Test for session fixation (default: True)
- test_jwt: Analyze JWT token security (default: True)
- test_lockout: Test brute force protection (default: True)
- test_mfa: Detect MFA presence (default: True)
- test_password_reset: Test password reset security (default: True)
- timing_samples: Number of samples for timing analysis (default: 5)
- max_lockout_attempts: Max attempts for lockout testing (default: 10)

References
----------
- OWASP A07:2025: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
- NIST 800-63b Digital Identity Guidelines
- CWE-287: Improper Authentication
- CWE-384: Session Fixation
- CWE-521: Weak Password Requirements

Author: Security Scanner Project
Version: 2.0.0
"""

import base64
import hashlib
import json
import math
import re
import statistics
import time
from collections import Counter
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from attacks.base import Finding, Severity
from attacks.owasp import OWASPRegistry
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase


@OWASPRegistry.register("a07")
class AuthFailuresAttack(BaseOWASPAttack):
    """
    Authentication Failures Scanner (OWASP A07:2025).

    A comprehensive security scanner that detects authentication and session
    management vulnerabilities in web applications. This scanner is designed
    to work against real-world websites while minimizing false positives.

    The scanner performs non-destructive testing and respects rate limits.
    It does not attempt to create accounts, modify data, or perform actions
    that could impact the target application's state (except for necessary
    login form submissions with test credentials).

    Attributes
    ----------
    name : str
        Human-readable name of the attack module.
    description : str
        Brief description of the scanner's purpose.
    category : OWASPCategory
        OWASP Top 10 category (A07_AUTH_FAILURES).

    Class Constants
    ---------------
    WEAK_PASSWORDS : List[str]
        Common weak passwords from breach databases for policy testing.
    DEFAULT_CREDENTIALS : List[Tuple[str, str]]
        Default username/password pairs commonly found in applications.
    TEST_USERNAMES : List[str]
        Usernames to test for enumeration vulnerabilities.
    AUTH_PATH_PATTERNS : Dict[str, List[str]]
        URL patterns for discovering authentication endpoints.
    AUTH_KEYWORDS : List[str]
        Keywords indicating authentication-related content.
    SESSION_COOKIE_PATTERNS : List[str]
        Common session cookie name patterns.

    Example
    -------
    Basic usage::

        scanner = AuthFailuresAttack()
        scanner.configure(
            timeout=10,
            test_default_credentials=True,
            test_jwt=True
        )

        for finding in scanner.run("https://example.com"):
            if finding.severity in [Severity.HIGH, Severity.CRITICAL]:
                print(f"ALERT: {finding.title}")
                print(f"  Evidence: {finding.evidence}")
                print(f"  Fix: {finding.remediation}")

    Notes
    -----
    - The scanner requires network access to the target.
    - Some tests may trigger rate limiting or account lockouts.
    - Configure `max_lockout_attempts` conservatively for production targets.
    - Results should be verified manually before reporting.

    See Also
    --------
    BaseOWASPAttack : Base class for OWASP attack modules.
    OWASPRegistry : Registry for discovering and instantiating attacks.
    """

    name = "Authentication Failures Scanner"
    description = "Detects authentication and session management vulnerabilities"
    category = OWASPCategory.A07_AUTH_FAILURES

    # =========================================================================
    # Class Constants - Password Lists
    # =========================================================================

    #: Extended list of weak passwords sourced from common breach databases.
    #: Includes passwords from RockYou, Adobe, and other major breaches.
    #: Used for testing password policy enforcement.
    WEAK_PASSWORDS: List[str] = [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111",
        "1234567",
        "dragon",
        "123123",
        "baseball",
        "iloveyou",
        "trustno1",
        "sunshine",
        "master",
        "welcome",
        "shadow",
        "ashley",
        "football",
        "jesus",
        "michael",
        "ninja",
        "mustang",
        "password1",
        "admin",
        "letmein",
        "abc123",
        "test",
        "guest",
        # Single/short passwords for policy testing
        "a",
        "aa",
        "aaa",
        "1",
        "12",
        "123",
    ]

    # =========================================================================
    # Class Constants - Default Credentials
    # =========================================================================

    #: Default credential pairs commonly found in web applications.
    #: Includes generic defaults (admin:admin) and CMS-specific credentials.
    #: Testing these credentials can reveal serious security misconfigurations.
    #: Format: List of (username, password) tuples.
    DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("admin", ""),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("user", "user"),
        ("user", "password"),
        ("test", "test"),
        ("guest", "guest"),
        ("demo", "demo"),
        # CMS-specific defaults
        ("admin", "admin@123"),
        ("wp-admin", "wp-admin"),
        ("joomla", "joomla"),
        ("drupal", "drupal"),
    ]

    # =========================================================================
    # Class Constants - Test Usernames
    # =========================================================================

    #: Common usernames used for enumeration testing.
    #: These are frequently used administrative or system accounts.
    #: The scanner tests these against the target to detect enumeration flaws.
    TEST_USERNAMES: List[str] = [
        "admin",
        "administrator",
        "root",
        "user",
        "test",
        "guest",
        "info",
        "support",
        "contact",
        "webmaster",
        "postmaster",
        "sales",
        "demo",
    ]

    # =========================================================================
    # Class Constants - Endpoint Discovery Patterns
    # =========================================================================

    #: URL path patterns for discovering authentication endpoints.
    #: Organized by endpoint type (login, register, forgot_password, etc.).
    #: Includes patterns for various frameworks (Django, Rails, WordPress, etc.).
    AUTH_PATH_PATTERNS: Dict[str, List[str]] = {
        "login": [
            "/login",
            "/signin",
            "/sign-in",
            "/auth/login",
            "/user/login",
            "/account/login",
            "/member/login",
            "/wp-login.php",
            "/admin/login",
            "/administrator",
            "/api/login",
            "/api/auth/login",
            "/api/v1/login",
            "/api/v1/auth/login",
            "/oauth/authorize",
            "/auth",
            "/session/new",
            "/users/sign_in",
        ],
        "register": [
            "/register",
            "/signup",
            "/sign-up",
            "/auth/register",
            "/user/register",
            "/account/register",
            "/create-account",
            "/join",
            "/api/register",
            "/api/auth/register",
            "/api/v1/register",
            "/users/sign_up",
        ],
        "forgot_password": [
            "/forgot-password",
            "/forgot",
            "/password/forgot",
            "/auth/forgot",
            "/reset",
            "/recover",
            "/password-reset",
            "/account/recover",
            "/api/forgot-password",
            "/api/auth/forgot",
            "/users/password/new",
        ],
        "logout": [
            "/logout",
            "/signout",
            "/sign-out",
            "/auth/logout",
            "/user/logout",
            "/api/logout",
            "/session/destroy",
            "/users/sign_out",
        ],
        "profile": [
            "/profile",
            "/account",
            "/user",
            "/me",
            "/api/me",
            "/api/user",
            "/api/profile",
            "/dashboard",
            "/admin",
        ],
    }

    #: Keywords that indicate authentication-related page content.
    #: Used to verify discovered endpoints are actually auth pages.
    AUTH_KEYWORDS: List[str] = [
        "login",
        "signin",
        "sign in",
        "log in",
        "username",
        "password",
        "email",
        "authenticate",
        "credential",
        "register",
        "signup",
        "sign up",
        "forgot",
        "reset",
        "recover",
        "remember me",
        "keep me logged",
        "stay signed",
    ]

    # =========================================================================
    # Class Constants - Session Cookie Patterns
    # =========================================================================

    #: Common session cookie name patterns across different platforms.
    #: Used to identify session cookies for security attribute analysis.
    #: Covers PHP, Java, .NET, ColdFusion, Node.js, and generic patterns.
    SESSION_COOKIE_PATTERNS: List[str] = [
        "session",
        "sessionid",
        "sess",
        "sid",
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspsessionid",
        "cfid",
        "cftoken",
        "connect.sid",
        "token",
        "auth",
        "jwt",
        "access_token",
    ]

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(self) -> None:
        """
        Initialize the Authentication Failures scanner.

        Sets up internal state for tracking discovered endpoints, forms,
        and session tokens during the scan.
        """
        super().__init__()
        #: Discovered authentication endpoints by type (login, register, etc.)
        self._discovered_endpoints: Dict[str, Optional[str]] = {}
        #: Authentication forms extracted from discovered pages
        self._discovered_forms: List[Dict[str, Any]] = []
        #: Session tokens collected during testing
        self._session_tokens: List[str] = []
        #: Number of samples for timing-based enumeration detection
        self._timing_samples: int = 5

    # =========================================================================
    # Configuration
    # =========================================================================

    def configure(self, **kwargs: Any) -> None:
        """
        Configure the authentication failures scanner.

        Extends the base configuration with A07-specific options for
        controlling which tests are performed and their parameters.

        Parameters
        ----------
        **kwargs : Any
            Configuration options. Supports all base options plus:

            test_password_policy : bool, default=True
                Test for weak password policy enforcement.
            test_enumeration : bool, default=True
                Test for username enumeration vulnerabilities.
            test_session : bool, default=True
                Test session management security.
            test_lockout : bool, default=True
                Test for account lockout mechanisms.
            test_default_credentials : bool, default=True
                Test common default credential pairs.
            test_jwt : bool, default=True
                Analyze JWT token security.
            test_session_fixation : bool, default=True
                Test for session fixation vulnerabilities.
            test_mfa : bool, default=True
                Detect multi-factor authentication presence.
            test_password_reset : bool, default=True
                Test password reset flow security.
            timing_samples : int, default=5
                Number of requests for timing analysis.
            max_lockout_attempts : int, default=10
                Maximum login attempts for lockout testing.

        Example
        -------
        >>> scanner = AuthFailuresAttack()
        >>> scanner.configure(
        ...     timeout=15,
        ...     test_default_credentials=True,
        ...     test_jwt=True,
        ...     max_lockout_attempts=5  # Conservative for production
        ... )
        """
        super().configure(**kwargs)
        self._config["test_password_policy"] = kwargs.get("test_password_policy", True)
        self._config["test_enumeration"] = kwargs.get("test_enumeration", True)
        self._config["test_session"] = kwargs.get("test_session", True)
        self._config["test_lockout"] = kwargs.get("test_lockout", True)
        self._config["test_default_credentials"] = kwargs.get(
            "test_default_credentials", True
        )
        self._config["test_jwt"] = kwargs.get("test_jwt", True)
        self._config["test_session_fixation"] = kwargs.get(
            "test_session_fixation", True
        )
        self._config["test_mfa"] = kwargs.get("test_mfa", True)
        self._config["test_password_reset"] = kwargs.get("test_password_reset", True)
        self._config["timing_samples"] = kwargs.get("timing_samples", 5)
        self._config["max_lockout_attempts"] = kwargs.get("max_lockout_attempts", 10)
        self._timing_samples = self._config["timing_samples"]

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
                "test_default_credentials": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for default credentials",
                },
                "test_jwt": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test JWT token security",
                },
                "test_session_fixation": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test for session fixation vulnerabilities",
                },
                "test_mfa": {
                    "type": "boolean",
                    "default": True,
                    "description": "Detect MFA presence and configuration",
                },
                "test_password_reset": {
                    "type": "boolean",
                    "default": True,
                    "description": "Test password reset security",
                },
                "timing_samples": {
                    "type": "integer",
                    "default": 5,
                    "description": "Number of samples for timing-based detection",
                },
                "max_lockout_attempts": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum attempts for lockout testing",
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
                detection_patterns=["password", "weak", "strength", "policy"],
            ),
            OWASPTestCase(
                name="Username Enumeration",
                description="Test for username enumeration via error messages",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=self.TEST_USERNAMES,
                detection_patterns=[
                    "not found",
                    "doesn't exist",
                    "invalid user",
                    "no account",
                ],
            ),
            OWASPTestCase(
                name="Default Credentials",
                description="Test for default username/password combinations",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=[f"{u}:{p}" for u, p in self.DEFAULT_CREDENTIALS[:5]],
                detection_patterns=["dashboard", "welcome", "admin panel", "logged in"],
            ),
            OWASPTestCase(
                name="Session Management",
                description="Test session token security and fixation",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=[],
                detection_patterns=["session", "cookie", "token", "sid"],
            ),
            OWASPTestCase(
                name="JWT Security",
                description="Test JWT token implementation security",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=["alg:none", "weak_secret"],
                detection_patterns=["eyJ", "Authorization: Bearer"],
            ),
            OWASPTestCase(
                name="Account Lockout",
                description="Test for missing account lockout policy",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=[],
                detection_patterns=[
                    "locked",
                    "too many attempts",
                    "try again",
                    "captcha",
                ],
            ),
            OWASPTestCase(
                name="MFA Detection",
                description="Detect presence and strength of MFA",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=[],
                detection_patterns=[
                    "2fa",
                    "mfa",
                    "otp",
                    "verification code",
                    "authenticator",
                ],
            ),
            OWASPTestCase(
                name="Password Reset",
                description="Test password reset flow security",
                category=OWASPCategory.A07_AUTH_FAILURES,
                payloads=[],
                detection_patterns=["reset", "token", "email sent", "recovery"],
            ),
        ]

    # =========================================================================
    # Phase 1: Enhanced Endpoint Discovery
    # =========================================================================

    def _discover_auth_endpoints(self, target: str) -> Dict[str, Optional[str]]:
        """
        Discover authentication-related endpoints using multiple strategies.

        Strategies:
        1. Check common authentication paths (server-side routes)
        2. Crawl homepage for auth-related links (including hash-based SPA routes)
        3. Parse HTML for forms with password fields
        4. Check for SPA hash-based routes (#/login, #!/login)
        5. Check API endpoints

        Notes:
            Supports Single Page Applications (SPAs) that use hash-based routing
            like Angular, React, and Vue applications (e.g., #/login, #!/login).
        """
        base_url = self._normalize_url(target)
        endpoints: Dict[str, Optional[str]] = {
            "login": None,
            "register": None,
            "forgot_password": None,
            "logout": None,
            "profile": None,
        }

        # Strategy 1: Check common server-side paths
        for endpoint_type, paths in self.AUTH_PATH_PATTERNS.items():
            if endpoints.get(endpoint_type):
                continue

            for path in paths:
                if self.is_cancelled():
                    return endpoints

                url = self._build_url(base_url, path)
                response = self._make_request(url)

                if response and response.status_code in [200, 401, 403]:
                    # Verify it's actually an auth page by checking content
                    if self._is_auth_page(response.text, endpoint_type):
                        endpoints[endpoint_type] = url
                        break

                time.sleep(self._delay_between_requests)

        # Strategy 2: Crawl homepage for links (includes hash-based routes)
        homepage_response = self._make_request(base_url)
        if homepage_response:
            # Extract standard links and hash-based SPA routes
            discovered = self._extract_auth_links(homepage_response.text, base_url)
            for endpoint_type, url in discovered.items():
                if not endpoints.get(endpoint_type):
                    endpoints[endpoint_type] = url

            # Strategy 3: Extract forms with password fields
            self._discovered_forms = self._extract_auth_forms(
                homepage_response.text, base_url
            )

            # Strategy 4: Check for SPA hash-based routes if not found yet
            if not endpoints.get("login"):
                spa_endpoints = self._discover_spa_routes(
                    homepage_response.text, base_url
                )
                for endpoint_type, url in spa_endpoints.items():
                    if not endpoints.get(endpoint_type):
                        endpoints[endpoint_type] = url

        self._discovered_endpoints = endpoints
        return endpoints

    def _discover_spa_routes(self, html: str, base_url: str) -> Dict[str, str]:
        """
        Discover SPA (Single Page Application) hash-based routes.

        SPAs like Angular, React, and Vue often use hash-based routing where
        the route is specified after a # symbol (e.g., #/login, #!/login).
        These routes are handled client-side by JavaScript.

        This method uses multiple strategies:
        1. Search for href="#/..." patterns in HTML
        2. Search for JavaScript route definitions in bundled JS files
        3. Detect SPA framework indicators and probe common routes

        Args:
            html: HTML content to search for route references
            base_url: Base URL of the application

        Returns:
            Dictionary mapping endpoint types to full URLs with hash routes
        """
        discovered = {}

        # Common hash-based route patterns for SPAs
        hash_route_patterns = {
            "login": [
                "#/login",
                "#!/login",
                "#login",
                "#/signin",
                "#/sign-in",
                "#/auth/login",
                "#/user/login",
                "#/account/login",
            ],
            "register": [
                "#/register",
                "#!/register",
                "#register",
                "#/signup",
                "#/sign-up",
                "#/auth/register",
            ],
            "forgot_password": [
                "#/forgot-password",
                "#!/forgot-password",
                "#/forgot",
                "#/reset-password",
                "#/password/forgot",
            ],
        }

        # Look for hash routes in href attributes
        href_pattern = r'href=["\']([#][^"\']*)["\']'
        hash_hrefs = re.findall(href_pattern, html, re.IGNORECASE)

        for href in hash_hrefs:
            href_lower = href.lower()

            # Check for login routes
            if any(kw in href_lower for kw in ["login", "signin", "sign-in"]):
                if "login" not in discovered:
                    discovered["login"] = base_url + href

            # Check for register routes
            elif any(kw in href_lower for kw in ["register", "signup", "sign-up"]):
                if "register" not in discovered:
                    discovered["register"] = base_url + href

            # Check for forgot password routes
            elif any(kw in href_lower for kw in ["forgot", "reset", "recover"]):
                if "forgot_password" not in discovered:
                    discovered["forgot_password"] = base_url + href

        # Look for route definitions in JavaScript (Angular, React Router, Vue)
        # Pattern: path: '/login' or route: '/login' or to: '/login'
        js_route_patterns = [
            r'path\s*:\s*["\']/?([^"\']+)["\']',
            r'route\s*:\s*["\']/?([^"\']+)["\']',
            r'to\s*:\s*["\']/?([^"\']+)["\']',
            r'navigate\s*\(\s*["\']/?([^"\']+)["\']',
            r'routerLink\s*=\s*["\']/?([^"\']+)["\']',
        ]

        for pattern in js_route_patterns:
            routes = re.findall(pattern, html, re.IGNORECASE)
            for route in routes:
                route_lower = route.lower()

                if any(kw in route_lower for kw in ["login", "signin"]):
                    if "login" not in discovered:
                        # Construct hash-based URL
                        discovered["login"] = f"{base_url}#/{route.lstrip('/')}"

                elif any(kw in route_lower for kw in ["register", "signup"]):
                    if "register" not in discovered:
                        discovered["register"] = f"{base_url}#/{route.lstrip('/')}"

        # Check if this is a SPA by looking for framework indicators
        spa_indicators = [
            "ng-app",  # Angular 1.x
            "ng-version",  # Angular 2+
            "<app-root",  # Angular
            "data-reactroot",  # React
            "__NEXT_DATA__",  # Next.js
            "data-v-",  # Vue.js
            "nuxt",  # Nuxt.js
            "__NUXT__",  # Nuxt.js
            'id="app"',  # Common Vue/React pattern
            'id="root"',  # Common React pattern
        ]

        is_spa = any(indicator in html for indicator in spa_indicators)

        # If this appears to be a SPA and we haven't found routes,
        # check the JavaScript bundles for route definitions
        if is_spa and not discovered:
            discovered = self._discover_routes_from_js_bundles(
                html, base_url, hash_route_patterns
            )

        return discovered

    def _discover_routes_from_js_bundles(
        self, html: str, base_url: str, route_patterns: Dict[str, List[str]]
    ) -> Dict[str, str]:
        """
        Discover SPA routes by analyzing JavaScript bundle files.

        SPAs typically load their routing configuration from bundled JavaScript
        files. This method extracts script URLs from the HTML and searches
        for route definitions in the main application bundle.

        Args:
            html: HTML content containing script references
            base_url: Base URL of the application
            route_patterns: Dictionary of endpoint types to route patterns

        Returns:
            Dictionary of discovered endpoints with their URLs
        """
        discovered = {}

        # Find script sources in HTML
        script_pattern = r'src=["\']([^"\']+\.js)["\']'
        scripts = re.findall(script_pattern, html)

        # Priority order for script files (main bundle usually contains routes)
        priority_keywords = ["main", "app", "bundle", "chunk", "vendor"]

        # Sort scripts by priority
        def script_priority(script: str) -> int:
            script_lower = script.lower()
            for i, kw in enumerate(priority_keywords):
                if kw in script_lower:
                    return i
            return len(priority_keywords)

        scripts_sorted = sorted(scripts, key=script_priority)

        # Check up to 3 scripts for route definitions
        for script_src in scripts_sorted[:3]:
            if self.is_cancelled():
                break

            # Skip CDN scripts
            if "cdnjs" in script_src or "cdn" in script_src:
                continue

            # Build full URL for the script
            if script_src.startswith("//"):
                script_url = "https:" + script_src
            elif script_src.startswith("http"):
                script_url = script_src
            elif script_src.startswith("/"):
                script_url = urljoin(base_url, script_src)
            else:
                script_url = urljoin(base_url + "/", script_src)

            try:
                response = self._make_request(script_url)
                if response and response.status_code == 200:
                    js_content = response.text

                    # Search for route definitions in the JS bundle
                    routes_found = self._extract_routes_from_js(js_content)

                    for endpoint_type, route in routes_found.items():
                        if endpoint_type not in discovered:
                            discovered[endpoint_type] = f"{base_url}#/{route}"

                    if discovered:
                        break  # Found routes, no need to check more scripts

            except Exception:
                continue

            time.sleep(self._delay_between_requests)

        return discovered

    def _extract_routes_from_js(self, js_content: str) -> Dict[str, str]:
        """
        Extract authentication route paths from JavaScript content.

        Searches for common route definition patterns used by Angular,
        React Router, Vue Router, and other SPA frameworks.

        Args:
            js_content: JavaScript source code content

        Returns:
            Dictionary mapping endpoint types to route paths
        """
        routes = {}

        js_lower = js_content.lower()

        # Check for login routes - look for simple route paths
        # Pattern matches "/login" or "login" with optional leading slash
        login_match = re.search(r'["\']/?login["\']', js_lower)
        if login_match:
            routes["login"] = "login"
        else:
            # Try signin variants
            signin_match = re.search(r'["\']/?(sign-?in)["\']', js_lower)
            if signin_match:
                routes["login"] = signin_match.group(1)

        # Check for register routes
        register_match = re.search(r'["\']/?register["\']', js_lower)
        if register_match:
            routes["register"] = "register"
        else:
            # Try signup variants
            signup_match = re.search(r'["\']/?(sign-?up)["\']', js_lower)
            if signup_match:
                routes["register"] = signup_match.group(1)

        # Check for forgot password routes
        forgot_match = re.search(r'["\']/?forgot-password["\']', js_lower)
        if forgot_match:
            routes["forgot_password"] = "forgot-password"
        else:
            # Try other variants
            forgot_alt = re.search(
                r'["\']/?(password[/-]?reset|reset[/-]?password|forgot)["\']',
                js_lower,
            )
            if forgot_alt:
                routes["forgot_password"] = forgot_alt.group(1)

        return routes

    def _is_auth_page(self, html: str, endpoint_type: str) -> bool:
        """Check if HTML content appears to be an authentication page."""
        html_lower = html.lower()

        if endpoint_type == "login":
            indicators = ["password", "login", "sign in", "username", "email"]
            return sum(1 for i in indicators if i in html_lower) >= 2

        elif endpoint_type == "register":
            indicators = [
                "password",
                "register",
                "sign up",
                "create account",
                "confirm password",
            ]
            return sum(1 for i in indicators if i in html_lower) >= 2

        elif endpoint_type == "forgot_password":
            indicators = ["email", "reset", "forgot", "recover", "password"]
            return sum(1 for i in indicators if i in html_lower) >= 2

        return "password" in html_lower or "login" in html_lower

    def _extract_auth_links(self, html: str, base_url: str) -> Dict[str, str]:
        """Extract authentication-related links from HTML."""
        discovered = {}

        # Find all href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, html, re.IGNORECASE)

        for href in hrefs:
            href_lower = href.lower()

            # Check for login links
            if any(
                kw in href_lower for kw in ["login", "signin", "sign-in", "auth/login"]
            ):
                if "login" not in discovered:
                    discovered["login"] = urljoin(base_url, href)

            # Check for register links
            elif any(
                kw in href_lower for kw in ["register", "signup", "sign-up", "join"]
            ):
                if "register" not in discovered:
                    discovered["register"] = urljoin(base_url, href)

            # Check for forgot password links
            elif any(
                kw in href_lower for kw in ["forgot", "reset", "recover", "password"]
            ):
                if "forgot_password" not in discovered:
                    discovered["forgot_password"] = urljoin(base_url, href)

        return discovered

    def _extract_auth_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms with password fields from HTML."""
        auth_forms = []
        forms = self._extract_forms_enhanced(html)

        for form in forms:
            # Check if form has password field
            has_password = any(
                field.get("type") == "password"
                or "password" in field.get("name", "").lower()
                for field in form.get("fields", [])
            )

            if has_password:
                # Normalize action URL
                action = form.get("action", "")
                if action:
                    form["action"] = urljoin(base_url, action)
                else:
                    form["action"] = base_url
                auth_forms.append(form)

        return auth_forms

    def _extract_forms_enhanced(self, html: str) -> List[Dict[str, Any]]:
        """Enhanced form extraction with field details."""
        forms = []

        # Match forms with all attributes
        form_pattern = r"<form([^>]*)>(.*?)</form>"

        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_attrs = form_match.group(1)
            form_content = form_match.group(2)

            # Extract action
            action_match = re.search(
                r'action=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE
            )
            action = action_match.group(1) if action_match else ""

            # Extract method
            method_match = re.search(
                r'method=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE
            )
            method = method_match.group(1).upper() if method_match else "GET"

            # Extract all input fields with details
            fields = []
            input_pattern = r"<input([^>]*)>"

            for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                input_attrs = input_match.group(1)

                name_match = re.search(
                    r'name=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE
                )
                type_match = re.search(
                    r'type=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE
                )
                value_match = re.search(
                    r'value=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE
                )
                id_match = re.search(
                    r'id=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE
                )

                field = {
                    "name": name_match.group(1) if name_match else "",
                    "type": type_match.group(1).lower() if type_match else "text",
                    "value": value_match.group(1) if value_match else "",
                    "id": id_match.group(1) if id_match else "",
                }

                if field["name"]:
                    fields.append(field)

            forms.append(
                {
                    "action": action,
                    "method": method,
                    "fields": fields,
                    "inputs": [f["name"] for f in fields],  # Backward compatibility
                }
            )

        return forms

    def _identify_form_fields(
        self, form: Dict
    ) -> Tuple[Optional[str], Optional[str], Dict[str, str]]:
        """
        Identify username, password, and hidden fields in a form.

        Returns:
            Tuple of (username_field, password_field, hidden_fields)
        """
        username_field = None
        password_field = None
        hidden_fields = {}

        username_indicators = ["username", "user", "email", "login", "account", "name"]
        password_indicators = ["password", "pass", "pwd", "secret"]

        for field in form.get("fields", []):
            field_name = field.get("name", "").lower()
            field_type = field.get("type", "").lower()

            if field_type == "hidden":
                hidden_fields[field["name"]] = field.get("value", "")

            elif field_type == "password" or any(
                p in field_name for p in password_indicators
            ):
                password_field = field["name"]

            elif field_type in ["text", "email"] or any(
                u in field_name for u in username_indicators
            ):
                if not username_field:
                    username_field = field["name"]

        return username_field, password_field, hidden_fields

    # =========================================================================
    # Phase 2: Username Enumeration Detection
    # =========================================================================

    def _test_username_enumeration(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Test for username enumeration via response analysis and timing."""
        if not self._config.get("test_enumeration", True):
            return

        login_url = endpoints.get("login")
        if not login_url:
            # Try to use discovered forms
            if self._discovered_forms:
                yield from self._test_enumeration_via_forms(target)
            return

        # Get login form
        response = self._make_request(login_url)
        if not response:
            return

        forms = self._extract_forms_enhanced(response.text)
        login_form = self._find_login_form(forms)

        if not login_form:
            return

        username_field, password_field, hidden_fields = self._identify_form_fields(
            login_form
        )

        if not username_field or not password_field:
            return

        form_action = login_form.get("action", "")
        form_url = urljoin(login_url, form_action) if form_action else login_url

        # Test 1: Response-based enumeration
        yield from self._test_response_enumeration(
            form_url, username_field, password_field, hidden_fields
        )

        # Test 2: Timing-based enumeration
        yield from self._test_timing_enumeration(
            form_url, username_field, password_field, hidden_fields
        )

        self.set_progress(20)

    def _find_login_form(self, forms: List[Dict]) -> Optional[Dict]:
        """Find the most likely login form from a list of forms."""
        for form in forms:
            has_password = any(
                f.get("type") == "password" for f in form.get("fields", [])
            )
            has_username = any(
                f.get("type") in ["text", "email"]
                or any(
                    u in f.get("name", "").lower()
                    for u in ["user", "email", "login", "name"]
                )
                for f in form.get("fields", [])
            )

            if has_password and has_username:
                return form

        return None

    def _test_response_enumeration(
        self,
        form_url: str,
        username_field: str,
        password_field: str,
        hidden_fields: Dict,
    ) -> Generator[Finding, None, None]:
        """Test for username enumeration via response differences."""
        responses = {}

        # Generate test cases
        test_users = [
            ("definitely_not_real_user_xyz123", "invalid"),
            ("admin", "likely_valid"),
            ("administrator", "likely_valid"),
            ("nonexistent_user_abc789", "invalid"),
        ]

        for username, user_type in test_users:
            if self.is_cancelled():
                return

            data = {
                username_field: username,
                password_field: "wrongpassword123",
                **hidden_fields,
            }

            response = self._make_request(form_url, method="POST", data=data)

            if response:
                responses[username] = {
                    "type": user_type,
                    "status": response.status_code,
                    "length": len(response.text),
                    "text": response.text,
                    "headers": dict(response.headers),
                }

            time.sleep(self._delay_between_requests)

        # Analyze responses
        yield from self._analyze_enumeration_responses(responses)

    def _analyze_enumeration_responses(
        self, responses: Dict
    ) -> Generator[Finding, None, None]:
        """Analyze responses for enumeration indicators."""
        if len(responses) < 2:
            return

        # Group by user type
        invalid_responses = [r for u, r in responses.items() if r["type"] == "invalid"]
        valid_responses = [
            r for u, r in responses.items() if r["type"] == "likely_valid"
        ]

        if not invalid_responses or not valid_responses:
            return

        # Check 1: Status code differences
        invalid_statuses = {r["status"] for r in invalid_responses}
        valid_statuses = {r["status"] for r in valid_responses}

        if invalid_statuses != valid_statuses:
            yield Finding(
                title="Username Enumeration via Status Code",
                severity=Severity.MEDIUM,
                description="The application returns different HTTP status codes for "
                "valid vs invalid usernames.",
                evidence=f"Invalid user status: {invalid_statuses}, "
                f"Valid user status: {valid_statuses}",
                remediation="Return identical status codes for all login failures.",
                metadata={
                    "invalid_statuses": list(invalid_statuses),
                    "valid_statuses": list(valid_statuses),
                },
            )

        # Check 2: Response length differences
        invalid_lengths = [r["length"] for r in invalid_responses]
        valid_lengths = [r["length"] for r in valid_responses]

        avg_invalid = statistics.mean(invalid_lengths) if invalid_lengths else 0
        avg_valid = statistics.mean(valid_lengths) if valid_lengths else 0
        length_diff = abs(avg_valid - avg_invalid)

        if length_diff > 50:
            yield Finding(
                title="Username Enumeration via Response Length",
                severity=Severity.MEDIUM,
                description="Login responses have significantly different lengths for "
                "valid vs invalid usernames.",
                evidence=f"Average length difference: {length_diff:.0f} bytes",
                remediation="Ensure login failure responses are identical regardless "
                "of username validity.",
                metadata={"length_difference": length_diff},
            )

        # Check 3: Error message differences
        error_patterns = [
            (r"user.*not.*found", "User not found"),
            (r"invalid.*user(name)?", "Invalid user"),
            (r"no.*account", "No account"),
            (r"doesn't?\s*exist", "Doesn't exist"),
            (r"unknown.*user", "Unknown user"),
            (r"incorrect.*user", "Incorrect user"),
            (r"user.*doesn't?\s*exist", "User doesn't exist"),
        ]

        for r in responses.values():
            text_lower = r["text"].lower()
            for pattern, description in error_patterns:
                if re.search(pattern, text_lower):
                    yield Finding(
                        title="Username Enumeration via Error Message",
                        severity=Severity.MEDIUM,
                        description="The application reveals username validity through "
                        "distinct error messages.",
                        evidence=f"Pattern found: '{description}'",
                        remediation="Use generic messages like 'Invalid credentials' "
                        "for all login failures.",
                        metadata={"pattern": pattern, "message_type": description},
                    )
                    return

    def _test_timing_enumeration(
        self,
        form_url: str,
        username_field: str,
        password_field: str,
        hidden_fields: Dict,
    ) -> Generator[Finding, None, None]:
        """Test for username enumeration via timing differences."""
        # Collect timing samples
        invalid_times = []
        valid_times = []

        invalid_user = "definitely_not_real_user_xyz123"
        valid_user = "admin"

        for _ in range(self._timing_samples):
            if self.is_cancelled():
                return

            # Test invalid user
            data = {
                username_field: invalid_user,
                password_field: "wrongpassword",
                **hidden_fields,
            }
            start = time.time()
            self._make_request(form_url, method="POST", data=data)
            invalid_times.append(time.time() - start)

            time.sleep(self._delay_between_requests)

            # Test valid user
            data[username_field] = valid_user
            start = time.time()
            self._make_request(form_url, method="POST", data=data)
            valid_times.append(time.time() - start)

            time.sleep(self._delay_between_requests)

        if len(invalid_times) < 3 or len(valid_times) < 3:
            return

        # Calculate statistics
        avg_invalid = statistics.mean(invalid_times)
        avg_valid = statistics.mean(valid_times)
        timing_diff = abs(avg_valid - avg_invalid)

        # Calculate standard deviation to account for jitter
        combined_stdev = statistics.stdev(invalid_times + valid_times)

        # Significant if difference is > 2x standard deviation and > 100ms
        if timing_diff > max(2 * combined_stdev, 0.1):
            yield Finding(
                title="Username Enumeration via Timing",
                severity=Severity.MEDIUM,
                description="Response times differ significantly between valid and "
                "invalid usernames, allowing timing-based enumeration.",
                evidence=(
                    f"Timing diff: {timing_diff * 1000:.0f}ms "
                    f"(invalid: {avg_invalid * 1000:.0f}ms, "
                    f"valid: {avg_valid * 1000:.0f}ms)"
                ),
                remediation="Implement constant-time comparison for username lookup "
                "or add random delays to normalize response times.",
                metadata={
                    "timing_difference_ms": timing_diff * 1000,
                    "avg_invalid_ms": avg_invalid * 1000,
                    "avg_valid_ms": avg_valid * 1000,
                },
            )

    def _test_enumeration_via_forms(
        self, target: str
    ) -> Generator[Finding, None, None]:
        """Test enumeration using discovered forms when login endpoint unknown."""
        for form in self._discovered_forms:
            username_field, password_field, hidden_fields = self._identify_form_fields(
                form
            )
            if username_field and password_field:
                form_url = form.get("action", target)
                yield from self._test_response_enumeration(
                    form_url, username_field, password_field, hidden_fields
                )
                break

    # =========================================================================
    # Phase 3: Credential Testing
    # =========================================================================

    def _test_default_credentials(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Test for default credentials on login forms."""
        if not self._config.get("test_default_credentials", True):
            return

        login_url = endpoints.get("login")
        if not login_url:
            return

        response = self._make_request(login_url)
        if not response:
            return

        forms = self._extract_forms_enhanced(response.text)
        login_form = self._find_login_form(forms)

        if not login_form:
            return

        username_field, password_field, hidden_fields = self._identify_form_fields(
            login_form
        )

        if not username_field or not password_field:
            return

        form_action = login_form.get("action", "")
        form_url = urljoin(login_url, form_action) if form_action else login_url

        # Get baseline failed login response
        baseline_data = {
            username_field: "definitely_not_real_user_xyz",
            password_field: "definitely_wrong_password_xyz",
            **hidden_fields,
        }
        baseline_response = self._make_request(
            form_url, method="POST", data=baseline_data
        )

        if not baseline_response:
            return

        baseline_indicators = self._get_login_indicators(baseline_response)

        # Test default credentials
        successful_creds = []

        for username, password in self.DEFAULT_CREDENTIALS:
            if self.is_cancelled():
                return

            data = {
                username_field: username,
                password_field: password,
                **hidden_fields,
            }

            response = self._make_request(form_url, method="POST", data=data)

            if response:
                if self._is_login_successful(response, baseline_indicators):
                    successful_creds.append((username, password))

            time.sleep(self._delay_between_requests)

        if successful_creds:
            creds_display = ", ".join(
                f"{u}:{p}" if p else f"{u}:(empty)" for u, p in successful_creds
            )
            yield Finding(
                title="Default Credentials Accepted",
                severity=Severity.CRITICAL,
                description="The application accepts default credentials, allowing "
                "unauthorized access.",
                evidence=f"Working credentials: {creds_display}",
                remediation="Remove or change all default credentials immediately. "
                "Implement a mandatory password change on first login.",
                metadata={
                    "credentials": [
                        {"username": u, "password": p} for u, p in successful_creds
                    ]
                },
            )

        self.set_progress(35)

    def _get_login_indicators(self, response) -> Dict[str, Any]:
        """Extract indicators from a login response for comparison."""
        return {
            "status": response.status_code,
            "length": len(response.text),
            "url": response.url,
            "cookies": list(response.cookies.keys()),
            "has_error": self._has_login_error(response.text),
        }

    def _has_login_error(self, html: str) -> bool:
        """Check if response contains login error indicators."""
        error_patterns = [
            r"invalid.*credential",
            r"incorrect.*password",
            r"wrong.*password",
            r"login.*failed",
            r"authentication.*failed",
            r"invalid.*username",
            r"error",
        ]
        html_lower = html.lower()
        return any(re.search(p, html_lower) for p in error_patterns)

    def _is_login_successful(self, response, baseline_indicators: Dict) -> bool:
        """Determine if a login attempt was successful."""
        # Check for redirect to different page (common success indicator)
        if response.url != baseline_indicators.get("url"):
            # Check if redirected to profile/dashboard
            success_urls = [
                "dashboard",
                "profile",
                "home",
                "admin",
                "account",
                "welcome",
            ]
            if any(s in response.url.lower() for s in success_urls):
                return True

        # Check for new session cookie
        current_cookies = list(response.cookies.keys())
        if len(current_cookies) > len(baseline_indicators.get("cookies", [])):
            return True

        # Check for success messages
        success_patterns = [
            r"welcome\s*,?\s*\w+",
            r"logged\s*in",
            r"login\s*successful",
            r"dashboard",
            r"my\s*account",
        ]
        html_lower = response.text.lower()
        if any(re.search(p, html_lower) for p in success_patterns):
            return True

        # Check if error messages disappeared
        if baseline_indicators.get("has_error") and not self._has_login_error(
            response.text
        ):
            return True

        return False

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

        forms = self._extract_forms_enhanced(response.text)

        # Find registration form
        reg_form = None
        for form in forms:
            has_password = any(
                f.get("type") == "password" for f in form.get("fields", [])
            )
            has_email = any(
                f.get("type") == "email"
                or "email" in f.get("name", "").lower()
                or "user" in f.get("name", "").lower()
                for f in form.get("fields", [])
            )
            if has_password and has_email:
                reg_form = form
                break

        if not reg_form:
            return

        username_field, password_field, hidden_fields = self._identify_form_fields(
            reg_form
        )

        # Check for confirm password field
        confirm_field = None
        for field in reg_form.get("fields", []):
            name_lower = field.get("name", "").lower()
            if (
                "confirm" in name_lower
                or "repeat" in name_lower
                or "verify" in name_lower
            ):
                confirm_field = field["name"]
                break

        if not username_field or not password_field:
            return

        form_action = reg_form.get("action", "")
        form_url = urljoin(register_url, form_action) if form_action else register_url

        # Test categories of weak passwords
        policy_issues = []

        # Test 1: Very short passwords (1-3 chars)
        for pwd in ["a", "12", "abc"]:
            if self.is_cancelled():
                return

            test_email = (
                f"test_{hashlib.md5(pwd.encode()).hexdigest()[:8]}@test.invalid"
            )
            data = {
                username_field: test_email,
                password_field: pwd,
                **hidden_fields,
            }
            if confirm_field:
                data[confirm_field] = pwd

            response = self._make_request(form_url, method="POST", data=data)
            if response and self._password_accepted(response.text):
                policy_issues.append(f"Very short password accepted: '{pwd}'")
                break

            time.sleep(self._delay_between_requests)

        # Test 2: Common weak passwords
        for pwd in ["password", "123456", "qwerty"]:
            if self.is_cancelled():
                return

            test_email = (
                f"test_{hashlib.md5(pwd.encode()).hexdigest()[:8]}@test.invalid"
            )
            data = {
                username_field: test_email,
                password_field: pwd,
                **hidden_fields,
            }
            if confirm_field:
                data[confirm_field] = pwd

            response = self._make_request(form_url, method="POST", data=data)
            if response and self._password_accepted(response.text):
                policy_issues.append(f"Common weak password accepted: '{pwd}'")
                break

            time.sleep(self._delay_between_requests)

        # Test 3: Numeric only
        for pwd in ["12345678", "87654321"]:
            if self.is_cancelled():
                return

            test_email = (
                f"test_{hashlib.md5(pwd.encode()).hexdigest()[:8]}@test.invalid"
            )
            data = {
                username_field: test_email,
                password_field: pwd,
                **hidden_fields,
            }
            if confirm_field:
                data[confirm_field] = pwd

            response = self._make_request(form_url, method="POST", data=data)
            if response and self._password_accepted(response.text):
                policy_issues.append("Numeric-only password accepted")
                break

            time.sleep(self._delay_between_requests)

        if policy_issues:
            yield Finding(
                title="Weak Password Policy",
                severity=Severity.HIGH,
                description="The application accepts weak passwords that don't meet "
                "security standards.",
                evidence="\n".join(policy_issues),
                remediation="Implement password requirements: minimum 8 characters, "
                "mix of character types. Check passwords against breached "
                "password databases (HIBP). Follow NIST 800-63b guidelines.",
                metadata={"policy_issues": policy_issues},
            )

        self.set_progress(50)

    def _password_accepted(self, html: str) -> bool:
        """Check if password was accepted (no rejection message)."""
        html_lower = html.lower()

        rejection_patterns = [
            r"password.*too.*short",
            r"password.*weak",
            r"password.*simple",
            r"password.*must",
            r"password.*require",
            r"password.*length",
            r"stronger.*password",
            r"password.*character",
            r"password.*invalid",
            r"minimum.*\d+.*character",
        ]

        # Check for rejection
        if any(re.search(p, html_lower) for p in rejection_patterns):
            return False

        # Check for success indicators
        success_patterns = [
            "success",
            "created",
            "registered",
            "welcome",
            "verify your email",
            "confirmation",
            "thank you",
        ]

        return any(p in html_lower for p in success_patterns)

    # =========================================================================
    # Phase 4: Session Management Security
    # =========================================================================

    def _test_session_security(self, target: str) -> Generator[Finding, None, None]:
        """Comprehensive session security testing."""
        if not self._config.get("test_session", True):
            return

        base_url = self._normalize_url(target)

        # Test cookie security
        yield from self._test_cookie_security(base_url)

        # Test session token entropy
        yield from self._test_session_entropy(base_url)

        # Test session fixation
        if self._config.get("test_session_fixation", True):
            yield from self._test_session_fixation(base_url)

        self.set_progress(65)

    def _test_cookie_security(self, base_url: str) -> Generator[Finding, None, None]:
        """Test cookie security attributes."""
        response = self._make_request(base_url)
        if not response:
            return

        # Get all Set-Cookie headers
        set_cookie_headers = response.headers.get("Set-Cookie", "")
        if isinstance(set_cookie_headers, str):
            set_cookie_headers = [set_cookie_headers] if set_cookie_headers else []

        # Also check response.cookies
        cookies_checked: Set[str] = set()

        for cookie in response.cookies:
            cookie_name = cookie.name
            cookie_value = cookie.value or ""
            cookie_name_lower = cookie_name.lower()

            # Check if this is a session-like cookie
            is_session_cookie = (
                any(
                    pattern in cookie_name_lower
                    for pattern in self.SESSION_COOKIE_PATTERNS
                )
                or len(cookie_value) > 20
            )

            if not is_session_cookie:
                continue

            if cookie_name in cookies_checked:
                continue
            cookies_checked.add(cookie_name)

            # Find the Set-Cookie header for this cookie
            cookie_header = ""
            for header in set_cookie_headers:
                if cookie_name in header:
                    cookie_header = header.lower()
                    break

            # Check HttpOnly
            if "httponly" not in cookie_header:
                yield Finding(
                    title="Session Cookie Missing HttpOnly Flag",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{cookie_name}' is missing the HttpOnly flag, "
                    "making it accessible to JavaScript and vulnerable to XSS theft.",
                    evidence=f"Cookie: {cookie_name}",
                    remediation="Set the HttpOnly flag on all session cookies.",
                    metadata={"cookie_name": cookie_name},
                )

            # Check Secure (only for HTTPS)
            parsed = urlparse(base_url)
            if parsed.scheme == "https" and "secure" not in cookie_header:
                yield Finding(
                    title="Session Cookie Missing Secure Flag",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{cookie_name}' is missing the Secure flag "
                    "on an HTTPS site, allowing transmission over HTTP.",
                    evidence=f"Cookie: {cookie_name}",
                    remediation="Set the Secure flag on all session cookies.",
                    metadata={"cookie_name": cookie_name},
                )

            # Check SameSite
            if "samesite" not in cookie_header:
                yield Finding(
                    title="Session Cookie Missing SameSite Attribute",
                    severity=Severity.LOW,
                    description=f"Cookie '{cookie_name}' is missing the SameSite "
                    "attribute, potentially vulnerable to CSRF.",
                    evidence=f"Cookie: {cookie_name}",
                    remediation="Set SameSite=Lax or Strict on session cookies.",
                    metadata={"cookie_name": cookie_name},
                )
            elif "samesite=none" in cookie_header:
                yield Finding(
                    title="Session Cookie with SameSite=None",
                    severity=Severity.LOW,
                    description=f"Cookie '{cookie_name}' has SameSite=None, allowing "
                    "cross-site requests.",
                    evidence=f"Cookie: {cookie_name}",
                    remediation="Use SameSite=Lax or SameSite=Strict unless cross-site "
                    "functionality is required.",
                    metadata={"cookie_name": cookie_name},
                )

            # Check for __Host- or __Secure- prefix
            if cookie_name.startswith("__Host-") or cookie_name.startswith("__Secure-"):
                # Verify requirements are met
                if cookie_name.startswith("__Host-"):
                    if "secure" not in cookie_header or "path=/" not in cookie_header:
                        yield Finding(
                            title="Invalid __Host- Cookie Prefix",
                            severity=Severity.LOW,
                            description=f"Cookie '{cookie_name}' uses __Host- prefix "
                            "but doesn't meet requirements (Secure + Path=/).",
                            evidence=f"Cookie: {cookie_name}",
                            remediation="Ensure __Host- cookies have Secure + Path=/.",
                            metadata={"cookie_name": cookie_name},
                        )

    def _test_session_entropy(self, base_url: str) -> Generator[Finding, None, None]:
        """Test session token entropy and randomness."""
        tokens = []

        # Collect multiple session tokens
        for _ in range(5):
            if self.is_cancelled():
                return

            # Create fresh session
            session = self._get_session()
            session.cookies.clear()

            response = self._make_request(base_url)
            if response:
                for cookie in response.cookies:
                    cookie_name_lower = cookie.name.lower()
                    if any(
                        p in cookie_name_lower for p in self.SESSION_COOKIE_PATTERNS
                    ):
                        tokens.append((cookie.name, cookie.value))
                        break

            time.sleep(self._delay_between_requests)

        if not tokens:
            return

        # Analyze token properties
        for cookie_name, token in tokens[:1]:  # Analyze first token type
            if not token:
                continue

            # Check length (should be at least 16 bytes / 128 bits)
            if len(token) < 16:
                yield Finding(
                    title="Short Session Token",
                    severity=Severity.HIGH,
                    description=f"Session token '{cookie_name}' is too short "
                    f"({len(token)} chars), indicating low entropy.",
                    evidence=f"Token length: {len(token)} characters",
                    remediation="Use session tokens with at least 128 bits of entropy "
                    "(typically 32+ characters).",
                    metadata={"cookie_name": cookie_name, "token_length": len(token)},
                )

            # Calculate Shannon entropy
            entropy = self._calculate_entropy(token)
            if entropy < 3.0:  # Low entropy threshold
                yield Finding(
                    title="Low Session Token Entropy",
                    severity=Severity.HIGH,
                    description=f"Session token '{cookie_name}' has low entropy "
                    f"({entropy:.2f} bits/char), making it predictable.",
                    evidence=f"Entropy: {entropy:.2f} bits per character",
                    remediation="Use cryptographically secure random generation "
                    "for session tokens.",
                    metadata={"cookie_name": cookie_name, "entropy": entropy},
                )

        # Check for sequential or predictable patterns
        if len(tokens) >= 3:
            token_values = [t[1] for t in tokens if t[1]]
            if self._tokens_are_sequential(token_values):
                yield Finding(
                    title="Sequential Session Tokens",
                    severity=Severity.CRITICAL,
                    description="Session tokens are sequential/predictable, "
                    "allowing hijacking.",
                    evidence=f"Tokens analyzed: {len(token_values)}",
                    remediation="Use cryptographically secure random number generators "
                    "for session token generation.",
                    metadata={"sample_count": len(token_values)},
                )

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not token:
            return 0.0

        counter = Counter(token)
        length = len(token)

        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _tokens_are_sequential(self, tokens: List[str]) -> bool:
        """Check if tokens appear to be sequential."""
        if len(tokens) < 2:
            return False

        # Try to find numeric portions
        numeric_parts = []
        for token in tokens:
            # Extract numbers from token
            numbers = re.findall(r"\d+", token)
            if numbers:
                numeric_parts.append(int(numbers[-1]))  # Use last number

        if len(numeric_parts) >= 2:
            # Check if numbers are sequential
            diffs = [
                numeric_parts[i + 1] - numeric_parts[i]
                for i in range(len(numeric_parts) - 1)
            ]
            if len(set(diffs)) == 1 and diffs[0] in [1, -1]:
                return True

        return False

    def _test_session_fixation(self, base_url: str) -> Generator[Finding, None, None]:
        """Test for session fixation vulnerability."""
        login_url = self._discovered_endpoints.get("login")
        if not login_url:
            return

        # Get initial session
        response1 = self._make_request(base_url)
        if not response1:
            return

        initial_sessions = {}
        for cookie in response1.cookies:
            cookie_name_lower = cookie.name.lower()
            if any(p in cookie_name_lower for p in self.SESSION_COOKIE_PATTERNS):
                initial_sessions[cookie.name] = cookie.value

        if not initial_sessions:
            return

        # Attempt login (we can't actually log in, but we can check behavior)
        response2 = self._make_request(login_url)
        if not response2:
            return

        forms = self._extract_forms_enhanced(response2.text)
        login_form = self._find_login_form(forms)

        if not login_form:
            return

        username_field, password_field, hidden_fields = self._identify_form_fields(
            login_form
        )

        if not username_field or not password_field:
            return

        form_action = login_form.get("action", "")
        form_url = urljoin(login_url, form_action) if form_action else login_url

        # Submit login with test credentials
        data = {
            username_field: "test_session_fixation_user",
            password_field: "test_password_123",
            **hidden_fields,
        }

        response3 = self._make_request(form_url, method="POST", data=data)
        if not response3:
            return

        # Check if session ID changed after login attempt
        post_login_sessions = {}
        for cookie in response3.cookies:
            cookie_name_lower = cookie.name.lower()
            if any(p in cookie_name_lower for p in self.SESSION_COOKIE_PATTERNS):
                post_login_sessions[cookie.name] = cookie.value

        # Compare sessions
        for cookie_name, initial_value in initial_sessions.items():
            if cookie_name in post_login_sessions:
                if post_login_sessions[cookie_name] == initial_value:
                    yield Finding(
                        title="Potential Session Fixation Vulnerability",
                        severity=Severity.HIGH,
                        description=f"Session ID '{cookie_name}' unchanged after "
                        "login, indicating potential session fixation.",
                        evidence=f"Cookie '{cookie_name}' unchanged after auth",
                        remediation="Regenerate session ID after authentication. "
                        "Invalidate old session.",
                        metadata={"cookie_name": cookie_name},
                    )

    # =========================================================================
    # Phase 5: JWT Security Testing
    # =========================================================================

    def _test_jwt_security(self, target: str) -> Generator[Finding, None, None]:
        """Test JWT token security."""
        if not self._config.get("test_jwt", True):
            return

        base_url = self._normalize_url(target)

        # Look for JWTs in responses
        jwt_locations = self._find_jwts(base_url)

        for location, token in jwt_locations:
            yield from self._analyze_jwt(token, location)

        self.set_progress(75)

    def _find_jwts(self, base_url: str) -> List[Tuple[str, str]]:
        """Find JWT tokens in responses."""
        jwts = []

        # Check main page and common endpoints
        endpoints = [base_url]
        if self._discovered_endpoints.get("login"):
            endpoints.append(self._discovered_endpoints["login"])
        if self._discovered_endpoints.get("profile"):
            endpoints.append(self._discovered_endpoints["profile"])

        for url in endpoints:
            response = self._make_request(url)
            if not response:
                continue

            # Check response body for JWT pattern
            jwt_pattern = r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
            matches = re.findall(jwt_pattern, response.text)
            for match in matches:
                jwts.append((f"Response body: {url}", match))

            # Check cookies
            for cookie in response.cookies:
                if re.match(jwt_pattern, cookie.value or ""):
                    jwts.append((f"Cookie: {cookie.name}", cookie.value))

            # Check Authorization header in any inline scripts
            auth_pattern = (
                r'["\']?Authorization["\']?\s*:\s*["\']Bearer\s+(eyJ[^"\']+)["\']'
            )
            auth_matches = re.findall(auth_pattern, response.text)
            for match in auth_matches:
                jwts.append((f"Script: {url}", match))

            time.sleep(self._delay_between_requests)

        return jwts

    def _analyze_jwt(self, token: str, location: str) -> Generator[Finding, None, None]:
        """Analyze a JWT token for security issues."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            # Decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            # Check 1: Algorithm none
            alg = header.get("alg", "").lower()
            if alg == "none":
                yield Finding(
                    title="JWT with Algorithm None",
                    severity=Severity.CRITICAL,
                    description="JWT uses 'none' algorithm, allowing token forgery.",
                    evidence=f"Location: {location}, Algorithm: {alg}",
                    remediation="Always validate a secure algorithm (RS256, ES256).",
                    metadata={"location": location, "algorithm": alg},
                )

            # Check 2: Weak algorithm
            if alg in ["hs256", "hs384", "hs512"]:
                yield Finding(
                    title="JWT Using Symmetric Algorithm",
                    severity=Severity.LOW,
                    description=f"JWT uses symmetric algorithm ({alg.upper()}). "
                    "Consider asymmetric algorithms for better security.",
                    evidence=f"Location: {location}, Algorithm: {alg.upper()}",
                    remediation="Consider asymmetric algorithms (RS256, ES256).",
                    metadata={"location": location, "algorithm": alg},
                )

            # Check 3: Missing expiration
            if "exp" not in payload:
                yield Finding(
                    title="JWT Missing Expiration",
                    severity=Severity.MEDIUM,
                    description="JWT has no expiration claim, valid indefinitely.",
                    evidence=f"Location: {location}",
                    remediation="Include 'exp' claim with reasonable expiration.",
                    metadata={"location": location},
                )
            else:
                # Check if expiration is too far in future
                exp = payload.get("exp", 0)
                current_time = time.time()
                if exp - current_time > 86400 * 30:  # More than 30 days
                    exp_seconds = exp - current_time
                    yield Finding(
                        title="JWT with Long Expiration",
                        severity=Severity.LOW,
                        description="JWT token expires more than 30 days from now.",
                        evidence=f"Location: {location}, Exp: {exp_seconds:.0f}s",
                        remediation="Use shorter token lifetimes with refresh tokens.",
                        metadata={
                            "location": location,
                            "expiration_seconds": exp_seconds,
                        },
                    )

            # Check 4: Sensitive data in payload
            sensitive_keys = ["password", "pwd", "secret", "ssn", "credit", "card"]
            for key in payload.keys():
                if any(s in key.lower() for s in sensitive_keys):
                    yield Finding(
                        title="JWT Contains Sensitive Data",
                        severity=Severity.HIGH,
                        description=f"JWT payload contains sensitive field: '{key}'",
                        evidence=f"Location: {location}, Field: {key}",
                        remediation="Never store sensitive data in JWT payloads.",
                        metadata={"location": location, "field": key},
                    )

            # Check 5: Missing audience/issuer
            if "aud" not in payload and "iss" not in payload:
                yield Finding(
                    title="JWT Missing Audience/Issuer Claims",
                    severity=Severity.LOW,
                    description="JWT lacks 'aud' and 'iss' claims for validation.",
                    evidence=f"Location: {location}",
                    remediation="Include 'aud' and 'iss' claims and validate them.",
                    metadata={"location": location},
                )

        except Exception:
            pass  # Invalid JWT format, skip analysis

    # =========================================================================
    # Phase 6: Rate Limiting and Brute Force Protection
    # =========================================================================

    def _test_rate_limiting(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Test for rate limiting and brute force protection."""
        if not self._config.get("test_lockout", True):
            return

        login_url = endpoints.get("login")
        if not login_url:
            return

        response = self._make_request(login_url)
        if not response:
            return

        forms = self._extract_forms_enhanced(response.text)
        login_form = self._find_login_form(forms)

        if not login_form:
            return

        username_field, password_field, hidden_fields = self._identify_form_fields(
            login_form
        )

        if not username_field or not password_field:
            return

        form_action = login_form.get("action", "")
        form_url = urljoin(login_url, form_action) if form_action else login_url

        max_attempts = self._config.get("max_lockout_attempts", 10)
        lockout_detected = False
        captcha_detected = False
        rate_limit_detected = False
        attempts = 0

        test_username = "admin"

        for i in range(max_attempts):
            if self.is_cancelled():
                return

            data = {
                username_field: test_username,
                password_field: f"wrongpassword{i}",
                **hidden_fields,
            }

            response = self._make_request(form_url, method="POST", data=data)
            attempts += 1

            if response:
                content_lower = response.text.lower()
                headers = {k.lower(): v for k, v in response.headers.items()}

                # Check for rate limit headers
                if any(
                    h in headers
                    for h in [
                        "x-ratelimit-remaining",
                        "x-rate-limit-remaining",
                        "retry-after",
                    ]
                ):
                    rate_limit_detected = True

                # Check for 429 status
                if response.status_code == 429:
                    rate_limit_detected = True
                    break

                # Check for lockout patterns
                lockout_patterns = [
                    "account.*locked",
                    "too many.*attempt",
                    "try again.*later",
                    "temporarily.*blocked",
                    "exceeded.*limit",
                    "wait.*minute",
                    "wait.*second",
                ]

                if any(re.search(p, content_lower) for p in lockout_patterns):
                    lockout_detected = True
                    break

                # Check for CAPTCHA
                captcha_patterns = [
                    "captcha",
                    "recaptcha",
                    "hcaptcha",
                    "g-recaptcha",
                    "challenge",
                    "verify.*human",
                    "robot",
                ]

                if any(p in content_lower for p in captcha_patterns):
                    captcha_detected = True
                    break

            time.sleep(0.1)  # Quick attempts

        # Generate findings
        if rate_limit_detected:
            yield Finding(
                title="Rate Limiting Detected",
                severity=Severity.INFO,
                description=f"Rate limiting activated after {attempts} attempts.",
                evidence=f"Rate limit triggered after {attempts} login attempts",
                remediation="N/A - Security control is in place",
                metadata={"attempts_to_trigger": attempts},
            )
        elif captcha_detected:
            yield Finding(
                title="CAPTCHA Protection Detected",
                severity=Severity.INFO,
                description=f"CAPTCHA challenge triggered after {attempts} attempts.",
                evidence=f"CAPTCHA appeared after {attempts} failed logins",
                remediation="N/A - Security control is in place",
                metadata={"attempts_to_trigger": attempts},
            )
        elif lockout_detected:
            yield Finding(
                title="Account Lockout Mechanism Present",
                severity=Severity.INFO,
                description=f"Account lockout detected after {attempts} attempts.",
                evidence=f"Lockout triggered after {attempts} failed attempts",
                remediation="N/A - Security control is in place",
                metadata={"attempts_to_lockout": attempts},
            )
        else:
            yield Finding(
                title="No Brute Force Protection Detected",
                severity=Severity.HIGH,
                description=f"No account lockout, rate limiting, or CAPTCHA after "
                f"{attempts} failed login attempts.",
                evidence=f"Attempted {attempts} failed logins without protection",
                remediation="Implement brute force protection: account lockout after "
                "3-5 failed attempts, progressive delays, CAPTCHA challenges, "
                "and/or IP-based rate limiting.",
                metadata={"attempts": attempts},
            )

        self.set_progress(85)

    # =========================================================================
    # Phase 7: MFA Detection
    # =========================================================================

    def _test_mfa_presence(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Detect presence and configuration of multi-factor authentication."""
        if not self._config.get("test_mfa", True):
            return

        mfa_indicators_found = []

        # Check login page for MFA references
        login_url = endpoints.get("login")
        if login_url:
            response = self._make_request(login_url)
            if response:
                mfa_patterns = [
                    (r"two.?factor", "Two-factor authentication reference"),
                    (r"2fa", "2FA reference"),
                    (r"mfa", "MFA reference"),
                    (r"authenticator", "Authenticator app reference"),
                    (r"verification.*code", "Verification code reference"),
                    (r"otp|one.?time", "OTP reference"),
                    (r"sms.*code", "SMS code reference"),
                    (r"google.*authenticator", "Google Authenticator reference"),
                    (r"security.*key", "Security key reference"),
                    (r"yubikey|fido|webauthn", "Hardware key reference"),
                ]

                content_lower = response.text.lower()
                for pattern, description in mfa_patterns:
                    if re.search(pattern, content_lower):
                        mfa_indicators_found.append(description)

        # Check profile/account page for MFA settings
        profile_url = endpoints.get("profile")
        if profile_url:
            response = self._make_request(profile_url)
            if response:
                content_lower = response.text.lower()

                setup_patterns = [
                    (r"enable.*2fa", "Enable 2FA option"),
                    (r"setup.*authenticator", "Setup authenticator option"),
                    (r"add.*security.*key", "Add security key option"),
                    (r"backup.*codes", "Backup codes reference"),
                ]

                for pattern, description in setup_patterns:
                    if re.search(pattern, content_lower):
                        mfa_indicators_found.append(description)

        if mfa_indicators_found:
            yield Finding(
                title="Multi-Factor Authentication Available",
                severity=Severity.INFO,
                description="The application supports multi-factor authentication.",
                evidence=f"MFA indicators: {', '.join(set(mfa_indicators_found))}",
                remediation="N/A - Security feature available. Consider enforcing MFA.",
                metadata={"indicators": list(set(mfa_indicators_found))},
            )
        else:
            yield Finding(
                title="No Multi-Factor Authentication Detected",
                severity=Severity.MEDIUM,
                description="No evidence of MFA support was found.",
                evidence="No MFA indicators in login or profile pages",
                remediation="Implement MFA to protect against credential compromise.",
                metadata={},
            )

        self.set_progress(90)

    # =========================================================================
    # Phase 8: Password Reset Security
    # =========================================================================

    def _test_password_reset(
        self, target: str, endpoints: Dict
    ) -> Generator[Finding, None, None]:
        """Test password reset flow security."""
        if not self._config.get("test_password_reset", True):
            return

        forgot_url = endpoints.get("forgot_password")
        if not forgot_url:
            return

        response = self._make_request(forgot_url)
        if not response:
            return

        forms = self._extract_forms_enhanced(response.text)

        # Find password reset form
        reset_form = None
        for form in forms:
            has_email = any(
                f.get("type") == "email" or "email" in f.get("name", "").lower()
                for f in form.get("fields", [])
            )
            if has_email:
                reset_form = form
                break

        if not reset_form:
            return

        email_field = None
        hidden_fields = {}

        for field in reset_form.get("fields", []):
            field_type = field.get("type", "").lower()
            field_name = field.get("name", "").lower()

            if field_type == "hidden":
                hidden_fields[field["name"]] = field.get("value", "")
            elif field_type == "email" or "email" in field_name:
                email_field = field["name"]

        if not email_field:
            return

        form_action = reset_form.get("action", "")
        form_url = urljoin(forgot_url, form_action) if form_action else forgot_url

        # Test 1: Check for user enumeration via password reset
        responses = {}

        test_emails = [
            ("admin@" + urlparse(target).netloc, "likely_valid"),
            ("definitely_not_real_xyz123@test.invalid", "invalid"),
        ]

        for email, email_type in test_emails:
            if self.is_cancelled():
                return

            data = {email_field: email, **hidden_fields}
            response = self._make_request(form_url, method="POST", data=data)

            if response:
                responses[email] = {
                    "type": email_type,
                    "status": response.status_code,
                    "length": len(response.text),
                    "text": response.text[:1000],
                }

            time.sleep(self._delay_between_requests)

        # Analyze for enumeration
        if len(responses) == 2:
            values = list(responses.values())

            # Check for different responses
            if values[0]["status"] != values[1]["status"]:
                yield Finding(
                    title="User Enumeration via Password Reset",
                    severity=Severity.MEDIUM,
                    description="Password reset returns different status codes "
                    "for valid vs invalid emails.",
                    evidence=f"Status: {values[0]['status']} vs {values[1]['status']}",
                    remediation="Return identical responses for all reset requests.",
                    metadata={"statuses": [v["status"] for v in values]},
                )

            length_diff = abs(values[0]["length"] - values[1]["length"])
            if length_diff > 100:
                yield Finding(
                    title="User Enumeration via Password Reset Response",
                    severity=Severity.MEDIUM,
                    description="Password reset returns different response lengths "
                    "for valid vs invalid emails.",
                    evidence=f"Length difference: {length_diff} bytes",
                    remediation="Return identical responses for all reset requests.",
                    metadata={"length_difference": length_diff},
                )

            # Check for explicit messages
            for email, data in responses.items():
                text_lower = data["text"].lower()
                enumeration_patterns = [
                    r"email.*not.*found",
                    r"no.*account",
                    r"user.*not.*exist",
                    r"invalid.*email",
                    r"unknown.*email",
                ]

                for pattern in enumeration_patterns:
                    if re.search(pattern, text_lower):
                        yield Finding(
                            title="User Enumeration via Password Reset Message",
                            severity=Severity.MEDIUM,
                            description="Password reset reveals email registration.",
                            evidence=f"Pattern in response for {data['type']} email",
                            remediation="Use generic message for all reset requests.",
                            metadata={"email_type": data["type"]},
                        )
                        break

        # Test 2: Check for host header injection (if reset link in response)
        injected_host = "evil.attacker.com"

        headers = {"Host": injected_host}
        data = {email_field: "test@test.invalid", **hidden_fields}

        response = self._make_request(
            form_url, method="POST", data=data, headers=headers
        )

        if response and injected_host in response.text:
            yield Finding(
                title="Host Header Injection in Password Reset",
                severity=Severity.HIGH,
                description="Password reset is vulnerable to host header injection, "
                "potentially allowing account takeover.",
                evidence=f"Injected host '{injected_host}' appears in response",
                remediation="Use a hardcoded domain for password reset links, "
                "or validate the Host header against a whitelist.",
                metadata={"injected_host": injected_host},
            )

        self.set_progress(95)

    # =========================================================================
    # Main Run Method
    # =========================================================================

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute comprehensive authentication failures security scan.

        Performs a complete assessment of the target's authentication and
        session management security, organized into eight testing phases:

        1. Endpoint Discovery (0-5%): Locate authentication endpoints
        2. Username Enumeration (5-20%): Test for user disclosure
        3. Default Credentials (20-35%): Test common credential pairs
        4. Password Policy (35-50%): Assess password requirements
        5. Session Management (50-65%): Analyze session security
        6. JWT Security (65-75%): Analyze token implementation
        7. Rate Limiting (75-85%): Test brute force protection
        8. MFA Detection (85-90%): Check for multi-factor auth
        9. Password Reset (90-95%): Test reset flow security

        Parameters
        ----------
        target : str
            The target URL to scan. Should be the base URL of the web
            application (e.g., "https://example.com").

        Yields
        ------
        Finding
            Security findings as they are discovered. Each Finding contains:
            - title: Brief description of the issue
            - severity: INFO, LOW, MEDIUM, HIGH, or CRITICAL
            - description: Detailed explanation
            - evidence: Proof of the vulnerability
            - remediation: How to fix the issue
            - metadata: Additional technical details

        Example
        -------
        >>> scanner = AuthFailuresAttack()
        >>> scanner.configure(timeout=10)
        >>> findings = list(scanner.run("https://target.com"))
        >>> critical = [f for f in findings if f.severity == Severity.CRITICAL]
        >>> print(f"Found {len(critical)} critical issues")

        Notes
        -----
        - Progress is reported via `set_progress()` (0-100%)
        - Scan can be cancelled via `cancel()` method
        - Respects `_delay_between_requests` for rate limiting
        - Errors are caught and reported as INFO findings
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Authentication Failures Scan Started",
            severity=Severity.INFO,
            description="Starting comprehensive authentication security scan",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Phase 1: Discover authentication endpoints
            self.set_progress(5)
            endpoints = self._discover_auth_endpoints(target)

            yield Finding(
                title="Authentication Endpoints Discovery",
                severity=Severity.INFO,
                description="Discovered authentication endpoints",
                evidence=f"Login: {endpoints.get('login')}, "
                f"Register: {endpoints.get('register')}, "
                f"Forgot Password: {endpoints.get('forgot_password')}",
                remediation="N/A - Informational",
                metadata={"endpoints": endpoints},
            )

            # Phase 2: Username Enumeration (0-20%)
            yield from self._test_username_enumeration(target, endpoints)

            # Phase 3: Default Credentials (20-35%)
            yield from self._test_default_credentials(target, endpoints)

            # Phase 3b: Password Policy (35-50%)
            yield from self._test_password_policy(target, endpoints)

            # Phase 4: Session Security (50-65%)
            yield from self._test_session_security(target)

            # Phase 5: JWT Security (65-75%)
            yield from self._test_jwt_security(target)

            # Phase 6: Rate Limiting (75-85%)
            yield from self._test_rate_limiting(target, endpoints)

            # Phase 7: MFA Detection (85-90%)
            yield from self._test_mfa_presence(target, endpoints)

            # Phase 8: Password Reset Security (90-95%)
            yield from self._test_password_reset(target, endpoints)

        except Exception as e:
            yield Finding(
                title="Scan Error",
                severity=Severity.INFO,
                description=f"An error occurred during scanning: {str(e)}",
                evidence=str(e),
                remediation="N/A - Error",
                metadata={"error": str(e)},
            )

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Authentication Failures Scan Completed",
            severity=Severity.INFO,
            description="Completed comprehensive authentication security scan",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
