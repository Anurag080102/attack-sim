"""
A01:2021 - Broken Access Control Attack Module.

This module implements detection of broken access control vulnerabilities including:
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Path traversal attempts
- Privilege escalation via parameter manipulation
"""

import math
import re
import socket
import time
from collections import deque
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from attacks.base import Finding, Severity
from attacks.owasp import OWASPRegistry
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase


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

    # Static resource extensions to filter out (noise filtering)
    STATIC_EXTENSIONS = {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".svg",
        ".ico",
        ".webp",
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".json",
        ".map",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".webm",
        ".mp3",
        ".wav",
        ".ogg",
        ".flac",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".zip",
        ".rar",
        ".tar",
        ".gz",
        ".7z",
    }

    # Static resource path patterns
    STATIC_PATH_PATTERNS = [
        r"/static/",
        r"/assets/",
        r"/images/",
        r"/img/",
        r"/css/",
        r"/js/",
        r"/fonts/",
        r"/media/",
        r"/uploads/",
        r"/public/",
        r"/dist/",
        r"/build/",
        r"/node_modules/",
        r"/vendor/",
        r"/lib/",
        r"/libs/",
        r"\.min\.",
    ]

    # Admin-related keywords for URL scoring
    ADMIN_KEYWORDS = {
        "admin",
        "administrator",
        "manage",
        "management",
        "dashboard",
        "control",
        "panel",
        "console",
        "config",
        "configuration",
        "settings",
        "setup",
        "system",
        "internal",
        "private",
        "secure",
        "protected",
        "restricted",
        "auth",
        "login",
        "user",
        "users",
        "account",
        "accounts",
        "profile",
        "role",
        "permission",
        "access",
        "privilege",
        "super",
        "root",
        "backup",
        "restore",
        "export",
        "import",
        "debug",
        "test",
        "dev",
        "staging",
        "api",
        "endpoint",
        "service",
        "monitor",
        "log",
        "logs",
    }

    # Suspicious file extensions for scoring
    SUSPICIOUS_EXTENSIONS = {
        ".bak",
        ".backup",
        ".old",
        ".orig",
        ".save",
        ".swp",
        ".tmp",
        ".config",
        ".cfg",
        ".conf",
        ".ini",
        ".env",
        ".sql",
        ".db",
        ".log",
        ".logs",
        ".txt",
        ".csv",
        ".xml",
    }

    # Fallback DNS servers
    FALLBACK_DNS_SERVERS = [
        "8.8.8.8",  # Google DNS
        "8.8.4.4",  # Google DNS Secondary
        "1.1.1.1",  # Cloudflare DNS
        "1.0.0.1",  # Cloudflare DNS Secondary
        "208.67.222.222",  # OpenDNS
        "208.67.220.220",  # OpenDNS Secondary
    ]

    # Aggressive testing: HTTP methods to try for bypass
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    # Header manipulation for bypass attempts
    BYPASS_HEADERS = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"X-Host": "localhost"},
        {"Forwarded": "for=127.0.0.1;host=localhost"},
    ]

    # Forced browsing: backup and temporary file patterns
    BACKUP_FILE_PATTERNS = [
        ".bak",
        ".backup",
        ".old",
        ".orig",
        ".save",
        ".swp",
        ".tmp",
        "~",
        ".1",
        ".2",
        ".copy",
        ".zip",
        ".tar.gz",
    ]

    # Parameter fuzzing patterns
    PARAM_FUZZ_PATTERNS = [
        ("id[]", "1"),
        ("id[0]", "1"),
        ("id[admin]", "true"),
        ("role", "admin"),
        ("admin", "1"),
        ("isAdmin", "true"),
        ("is_admin", "1"),
        ("type", "admin"),
        ("user_type", "admin"),
        ("debug", "1"),
        ("test", "1"),
        ("dev", "1"),
        ("admin_mode", "1"),
    ]

    # Cookie manipulation patterns
    COOKIE_MANIPULATION = [
        {"role": "admin"},
        {"isAdmin": "true"},
        {"is_admin": "1"},
        {"admin": "1"},
        {"user_type": "admin"},
        {"privilege": "admin"},
        {"access_level": "99"},
    ]

    def __init__(self):
        super().__init__()
        self._test_paths: List[str] = []
        self._discovered_urls: Set[str] = set()
        self._crawled_urls: Set[str] = set()
        self._scored_urls: List[Tuple[str, float]] = []

        # ALWAYS AGGRESSIVE - set defaults immediately
        self._config["test_http_methods"] = True
        self._config["test_header_bypass"] = True
        self._config["test_forced_browsing"] = True
        self._config["test_param_fuzzing"] = True
        self._config["test_cookie_manipulation"] = True
        self._config["test_idor"] = True
        self._config["test_path_traversal"] = True
        self._config["enable_crawling"] = True
        self._config["idor_range"] = 10
        self._config["crawl_depth"] = 3
        self._config["max_crawl_urls"] = 50

    def configure(self, **kwargs) -> None:
        """
        Configure broken access control attack parameters.
        Always runs in full aggressive mode - no configuration needed.
        """
        super().configure(**kwargs)

        # ALWAYS AGGRESSIVE - all bypass techniques enabled by default
        self._config["test_http_methods"] = True
        self._config["test_header_bypass"] = True
        self._config["test_forced_browsing"] = True
        self._config["test_param_fuzzing"] = True
        self._config["test_cookie_manipulation"] = True
        self._config["test_idor"] = True
        self._config["test_path_traversal"] = True
        self._config["enable_crawling"] = True
        self._config["idor_range"] = 10
        self._config["additional_paths"] = []
        self._config["crawl_depth"] = 3
        self._config["max_crawl_urls"] = 50

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        # No additional config needed - always runs full aggressive scan
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

    def _check_dns_resolution(self, hostname: str) -> Optional[str]:
        """
        Check if hostname can be resolved to an IP address.
        Try fallback DNS servers if system DNS fails.

        Args:
            hostname: Hostname to resolve

        Returns:
            Resolved IP address or None if resolution fails
        """
        # Try system DNS first
        try:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except socket.gaierror:
            pass

        # Try with dnspython if available (fallback DNS servers)
        try:
            import dns.resolver

            for dns_server in self.FALLBACK_DNS_SERVERS:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    answers = resolver.resolve(hostname, "A")
                    if answers:
                        return str(answers[0])
                except Exception:
                    continue
        except ImportError:
            # dnspython not available, that's okay - we tried system DNS
            pass

        return None

    def _check_host_availability(
        self, hostname: str, port: int = 80, timeout: int = 5
    ) -> bool:
        """
        Check if host is reachable on specified port.

        Args:
            hostname: Host to check
            port: Port to check (default: 80)
            timeout: Connection timeout in seconds

        Returns:
            True if host is reachable, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _is_static_resource(self, url: str) -> bool:
        """
        Check if URL points to a static resource (noise filtering).

        Args:
            url: URL to check

        Returns:
            True if URL is a static resource, False otherwise
        """
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check file extension
        for ext in self.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True

        # Check path patterns
        for pattern in self.STATIC_PATH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True

        return False

    def _calculate_url_entropy(self, url: str) -> float:
        """
        Calculate Shannon entropy of URL path to detect random-looking URLs.
        Random URLs often hide sensitive endpoints.

        Args:
            url: URL to analyze

        Returns:
            Entropy value (higher = more random)
        """
        parsed = urlparse(url)
        path = parsed.path

        if not path or path == "/":
            return 0.0

        # Calculate character frequency
        char_freq = {}
        for char in path:
            char_freq[char] = char_freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        path_len = len(path)
        for count in char_freq.values():
            probability = count / path_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _score_url(self, url: str) -> float:
        """
        Score URL based on likelihood of being an admin/sensitive endpoint.
        Uses ML-like heuristics without actual machine learning.

        Scoring factors:
        - Admin-related keywords (+20 points per keyword)
        - URL depth (+5 points per level)
        - Suspicious file extensions (+30 points)
        - High entropy (random-looking) (+15 points if entropy > 3.5)

        Args:
            url: URL to score

        Returns:
            Score (0-100+, higher = more likely to be sensitive)
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = f"{path}?{query}".lower()

        score = 0.0

        # Check for admin keywords
        keyword_count = 0
        for keyword in self.ADMIN_KEYWORDS:
            if keyword in full_url:
                score += 20
                keyword_count += 1

        # URL depth (more nested = potentially more sensitive)
        depth = len([p for p in path.split("/") if p])
        score += depth * 5

        # Suspicious file extensions
        for ext in self.SUSPICIOUS_EXTENSIONS:
            if path.endswith(ext):
                score += 30
                break

        # High entropy (random-looking URLs)
        entropy = self._calculate_url_entropy(url)
        if entropy > 3.5:
            score += 15

        # Bonus for API endpoints
        if "/api/" in path:
            score += 10

        return min(score, 100)  # Cap at 100

    def _crawl_website(self, target: str) -> Set[str]:
        """
        Crawl website to discover URLs for testing.
        Uses BFS (breadth-first search) to discover links.

        Args:
            target: Base URL to start crawling from

        Returns:
            Set of discovered URLs
        """
        if not self._config.get("enable_crawling", True):
            return set()

        base_url = self._normalize_url(target)
        parsed_base = urlparse(base_url)

        discovered_urls = set()
        crawled_urls = set()
        queue = deque([(base_url, 0)])  # (url, depth)

        max_depth = self._config.get("crawl_depth", 3)
        max_urls = self._config.get("max_crawl_urls", 100)

        while queue and len(discovered_urls) < max_urls:
            if self.is_cancelled():
                break

            current_url, depth = queue.popleft()

            if current_url in crawled_urls or depth > max_depth:
                continue

            # Skip static resources
            if self._is_static_resource(current_url):
                continue

            crawled_urls.add(current_url)

            try:
                response = self._make_request(current_url)
                if not response or response.status_code != 200:
                    continue

                # Parse HTML to find links
                soup = BeautifulSoup(response.text, "html.parser")

                # Extract all links
                for link_tag in soup.find_all(["a", "link", "script", "img", "form"]):
                    href = (
                        link_tag.get("href")
                        or link_tag.get("src")
                        or link_tag.get("action")
                    )

                    if not href:
                        continue

                    # Resolve relative URLs
                    absolute_url = urljoin(current_url, href)
                    parsed = urlparse(absolute_url)

                    # Only crawl same domain
                    if parsed.netloc != parsed_base.netloc:
                        continue

                    # Remove fragment
                    clean_url = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            parsed.query,
                            "",
                        )
                    )

                    if (
                        clean_url not in discovered_urls
                        and clean_url not in crawled_urls
                    ):
                        discovered_urls.add(clean_url)
                        if not self._is_static_resource(clean_url):
                            queue.append((clean_url, depth + 1))

                time.sleep(self._delay_between_requests)

            except Exception:
                continue

        return discovered_urls

    def _analyze_response_content(self, url: str, response: Any) -> Optional[Finding]:
        """
        Analyze response content for signs of broken access control.
        Enhanced detection with multiple heuristics.

        Args:
            url: URL that was tested
            response: HTTP response object

        Returns:
            Finding if vulnerability detected, None otherwise
        """
        if not response or response.status_code != 200:
            return None

        content = response.text
        content_lower = content.lower()

        # Admin UI indicators
        admin_ui_patterns = [
            r"<title>.*admin.*</title>",
            r"<h1>.*admin.*</h1>",
            r"admin\s+panel",
            r"administration\s+dashboard",
            r"control\s+panel",
            r"manage\s+users",
            r"user\s+management",
            r"system\s+settings",
            r"configuration\s+panel",
        ]

        ui_matches = []
        for pattern in admin_ui_patterns:
            if re.search(pattern, content_lower):
                ui_matches.append(pattern)

        # Admin action indicators
        admin_actions = [
            "delete user",
            "remove user",
            "add user",
            "create user",
            "edit permissions",
            "modify role",
            "grant access",
            "revoke access",
            "change password",
            "reset password",
            "export data",
            "import data",
            "backup",
            "restore",
        ]

        action_matches = [action for action in admin_actions if action in content_lower]

        # Directory listing indicators
        directory_listing = any(
            [
                "<title>index of" in content_lower,
                "parent directory" in content_lower,
                re.search(r'<a href="[^"]*/">.*\[dir\]', content_lower),
            ]
        )

        # API endpoint indicators
        api_indicators = [
            '"users":',
            '"accounts":',
            '"profiles":',
            "/api/admin",
            "/api/users",
            "/api/config",
        ]
        api_detected = any(indicator in content_lower for indicator in api_indicators)

        # Check for missing authentication redirect
        no_auth_redirect = not any(
            [
                response.status_code in [301, 302, 303, 307, 308],
                "login" in content_lower and response.url != url,
                "authentication required" in content_lower,
            ]
        )

        # Check security headers
        missing_headers = []
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ]

        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)

        # Determine if this is a vulnerability
        severity = Severity.INFO
        issues = []

        if ui_matches or action_matches:
            severity = Severity.HIGH
            if ui_matches:
                issues.append(f"Admin UI detected: {len(ui_matches)} patterns matched")
            if action_matches:
                issues.append(f"Admin actions found: {', '.join(action_matches[:3])}")

        if directory_listing:
            severity = Severity.MEDIUM
            issues.append("Directory listing exposed")

        if api_detected:
            issues.append("Admin API endpoints detected")
            if severity == Severity.INFO:
                severity = Severity.MEDIUM

        if no_auth_redirect and (ui_matches or action_matches):
            issues.append("No authentication/redirect enforced")

        if missing_headers and severity != Severity.INFO:
            issues.append(f"Missing security headers: {', '.join(missing_headers[:2])}")

        # Only report if significant issues found
        if severity != Severity.INFO and issues:
            return Finding(
                title="Broken Access Control Detected",
                severity=severity,
                description="Sensitive administrative content accessible without proper authorization",
                evidence=f"URL: {url}\nIssues found:\n"
                + "\n".join(f"- {issue}" for issue in issues),
                remediation=(
                    "1. Implement proper authentication and authorization checks\n"
                    "2. Use role-based access control (RBAC)\n"
                    "3. Add security headers\n"
                    "4. Disable directory listings\n"
                    "5. Protect API endpoints with authentication"
                ),
                metadata={
                    "url": url,
                    "issues": issues,
                    "missing_headers": missing_headers,
                },
            )

        return None

    def _test_protected_paths(self, target: str) -> Generator[Finding, None, None]:
        """
        Test access to protected paths without authentication.
        Now with crawling and intelligent URL scoring.
        """
        base_url = self._normalize_url(target)

        # Start with predefined paths
        all_paths = list(
            self.PROTECTED_PATHS + self._config.get("additional_paths", [])
        )

        # Crawl website to discover additional URLs
        if self._config.get("enable_crawling", True):
            discovered = self._crawl_website(target)
            self._discovered_urls = discovered

            # Score discovered URLs and add high-scoring ones to test
            scored_urls = []
            for url in discovered:
                score = self._score_url(url)
                if score > 30:  # Only test URLs with significant score
                    scored_urls.append((url, score))

            # Sort by score (highest first) and add to test list
            scored_urls.sort(key=lambda x: x[1], reverse=True)
            self._scored_urls = scored_urls

            # Extract paths from high-scoring URLs
            for url, score in scored_urls[:50]:  # Limit to top 50
                parsed = urlparse(url)
                path_with_query = parsed.path
                if parsed.query:
                    path_with_query += f"?{parsed.query}"
                if path_with_query not in all_paths:
                    all_paths.append(path_with_query)

        total_paths = len(all_paths)
        found_urls = set()  # Track already reported URLs to avoid duplicates

        for idx, path in enumerate(all_paths):
            if self.is_cancelled():
                break

            url = self._build_url(base_url, path)

            # Skip static resources
            if self._is_static_resource(url):
                continue

            response = self._make_request(url)

            if response and response.status_code == 200:
                # Normalize URL for deduplication (remove trailing slash)
                normalized_url = response.url.rstrip("/")

                # Skip if we already reported this URL
                if normalized_url in found_urls:
                    continue

                # Use enhanced content analysis
                finding = self._analyze_response_content(url, response)
                if finding:
                    found_urls.add(normalized_url)
                    yield finding

            # Update progress for this section (0-33%)
            self.set_progress((idx + 1) / total_paths * 33)
            time.sleep(self._delay_between_requests)

    def _test_path_traversal(self, target: str) -> Generator[Finding, None, None]:
        """Test for path traversal vulnerabilities (optimized)."""
        if not self._config.get("test_path_traversal", True):
            return

        base_url = self._normalize_url(target)

        # Reduced test set for speed (only most common endpoints and payloads)
        test_endpoints = ["/file", "/download", "/read"]
        # Only test most effective payloads
        common_payloads = ["../", "..\\", "%2e%2e%2f"]
        # Only test most common sensitive files
        common_files = ["etc/passwd", "windows/win.ini"]

        total_tests = len(test_endpoints) * len(common_payloads) * len(common_files)
        current_test = 0

        for endpoint in test_endpoints:
            for payload in common_payloads:
                for sensitive_file in common_files:
                    if self.is_cancelled():
                        return

                    # Test only 2 most common parameter patterns (reduced from 4)
                    test_urls = [
                        f"{base_url}{endpoint}?file={payload}{sensitive_file}",
                        f"{base_url}{endpoint}?path={payload}{sensitive_file}",
                    ]

                    for test_url in test_urls:
                        response = self._make_request(test_url)

                        if response and response.status_code == 200:
                            # Check for signs of file content disclosure
                            if self._check_path_traversal_success(
                                response.text, sensitive_file
                            ):
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
                                # Stop testing this endpoint once vulnerability found
                                break

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
        """Test for Insecure Direct Object Reference vulnerabilities (optimized)."""
        if not self._config.get("test_idor", True):
            return

        base_url = self._normalize_url(target)
        idor_range = self._config.get("idor_range", 5)

        # Reduced endpoint list for speed (only most common)
        test_endpoints = [
            "/api/user/{id}",
            "/api/profile/{id}",
            "/user/{id}",
            "/profile/{id}",
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

                    test_url = self._build_url(
                        base_url, endpoint.replace("{id}", str(test_id))
                    )
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
                                    "baseline_length": baseline_responses[endpoint][
                                        "length"
                                    ],
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

    def _test_http_method_bypass(self, target: str) -> Generator[Finding, None, None]:
        """Test different HTTP methods to bypass access controls."""
        if not self._config.get("test_http_methods", False):
            return

        base_url = self._normalize_url(target)
        test_paths = ["/admin", "/api/admin", "/admin/users", "/config"]

        vulnerable_methods = []
        vulnerable_paths = {}

        for path in test_paths:
            if self.is_cancelled():
                return

            url = self._build_url(base_url, path)

            # Test each HTTP method
            for method in self.HTTP_METHODS:
                response = self._make_request(url, method=method)

                # Only flag as vulnerable if:
                # 1. Status code is 200
                # 2. Method is not GET (GET is expected)
                # 3. Method is not OPTIONS (OPTIONS is normal for CORS)
                # 4. Response contains actual protected content (not just login page)
                if (
                    response
                    and response.status_code == 200
                    and method not in ["GET", "OPTIONS"]
                ):
                    # Verify this isn't just a redirect to login or empty response
                    finding = self._analyze_response_content(url, response)
                    if (
                        finding
                    ):  # Only flag if content analysis confirms protected access
                        vulnerable_methods.append(method)
                        if method not in vulnerable_paths:
                            vulnerable_paths[method] = []
                        vulnerable_paths[method].append(url)

                time.sleep(self._delay_between_requests)

        # Yield single consolidated finding if vulnerabilities found
        if vulnerable_methods:
            unique_methods = sorted(set(vulnerable_methods))

            # Determine severity based on methods found
            # DELETE, PUT, PATCH on admin endpoints = HIGH
            # POST on admin endpoints = MEDIUM (common but still concerning)
            dangerous_methods = {"DELETE", "PUT", "PATCH"}
            has_dangerous = any(m in dangerous_methods for m in unique_methods)
            severity = Severity.HIGH if has_dangerous else Severity.MEDIUM

            method_details = "\n".join(
                [
                    f"- {method}: {len(vulnerable_paths[method])} path(s) ({', '.join(vulnerable_paths[method][:2])}{'...' if len(vulnerable_paths[method]) > 2 else ''})"
                    for method in unique_methods
                ]
            )

            yield Finding(
                title="HTTP Method Bypass Vulnerabilities",
                severity=severity,
                description=f"Protected resources accessible via {len(unique_methods)} different HTTP methods that should be blocked",
                evidence=f"Vulnerable methods:\n{method_details}",
                remediation="Implement proper method-based access controls. Configure web server to only allow necessary HTTP methods (typically GET and POST). Block PUT, DELETE, PATCH, HEAD, OPTIONS on protected resources unless explicitly required.",
                metadata={
                    "vulnerable_methods": unique_methods,
                    "vulnerable_paths": vulnerable_paths,
                    "total_bypasses": len(vulnerable_methods),
                },
            )

    def _test_header_bypass(self, target: str) -> Generator[Finding, None, None]:
        """Test header manipulation for access control bypass."""
        if not self._config.get("test_header_bypass", False):
            return

        base_url = self._normalize_url(target)
        test_paths = ["/admin", "/api/admin", "/internal", "/restricted"]

        vulnerable_headers = []
        vulnerable_paths = set()

        for path in test_paths:
            if self.is_cancelled():
                return

            url = self._build_url(base_url, path)

            # Test each bypass header
            for bypass_header in self.BYPASS_HEADERS:
                response = self._make_request(url, headers=bypass_header)

                if response and response.status_code == 200:
                    finding = self._analyze_response_content(url, response)
                    if finding:
                        header_name = list(bypass_header.keys())[0]
                        vulnerable_headers.append(header_name)
                        vulnerable_paths.add(url)

                time.sleep(self._delay_between_requests)

        # Yield single consolidated finding if vulnerabilities found
        if vulnerable_headers:
            unique_headers = sorted(set(vulnerable_headers))
            yield Finding(
                title="Header Manipulation Bypass Vulnerabilities",
                severity=Severity.MEDIUM,
                description=f"Access control can be bypassed using {len(unique_headers)} different header manipulation techniques",
                evidence=f"Vulnerable headers: {', '.join(unique_headers)}\nAffected paths: {len(vulnerable_paths)} ({', '.join(list(vulnerable_paths)[:3])}{'...' if len(vulnerable_paths) > 3 else ''})",
                remediation="Implement proper access control that cannot be bypassed by request headers. Validate authentication on the server side, not based on client-supplied headers.",
                metadata={
                    "vulnerable_headers": unique_headers,
                    "vulnerable_paths": list(vulnerable_paths),
                    "total_bypasses": len(vulnerable_headers),
                },
            )

    def _test_forced_browsing(self, target: str) -> Generator[Finding, None, None]:
        """Test for exposed backup and temporary files."""
        if not self._config.get("test_forced_browsing", False):
            return

        base_url = self._normalize_url(target)

        # Common admin files to check for backups
        sensitive_files = [
            "/admin.php",
            "/config.php",
            "/database.php",
            "/settings.php",
            "/web.config",
            "/app.config",
            "/.env",
            "/config.json",
        ]

        exposed_files = []

        for file_path in sensitive_files:
            if self.is_cancelled():
                return

            # Test original file
            original_url = self._build_url(base_url, file_path)

            # Test with backup extensions
            for pattern in self.BACKUP_FILE_PATTERNS:
                test_url = original_url + pattern
                response = self._make_request(test_url)

                if response and response.status_code == 200:
                    # Check if it's not just a 404 page
                    if (
                        len(response.text) > 100
                        and "not found" not in response.text.lower()
                    ):
                        exposed_files.append(
                            {
                                "url": test_url,
                                "file": file_path,
                                "pattern": pattern,
                                "size": len(response.text),
                            }
                        )

                time.sleep(self._delay_between_requests)

        # Yield single consolidated finding if backup files found
        if exposed_files:
            file_details = "\n".join(
                [
                    f"- {f['file']}{f['pattern']} ({f['size']} bytes)"
                    for f in exposed_files
                ]
            )
            urls_list = "\n".join([f"  {f['url']}" for f in exposed_files[:5]])
            if len(exposed_files) > 5:
                urls_list += f"\n  ... and {len(exposed_files) - 5} more"

            yield Finding(
                title="Exposed Backup and Temporary Files",
                severity=Severity.HIGH,
                description=f"Found {len(exposed_files)} exposed backup/temporary files that may contain sensitive information",
                evidence=f"Exposed files:\n{file_details}\n\nURLs:\n{urls_list}",
                remediation="1. Remove all backup and temporary files from web-accessible directories\n2. Configure web server to deny access to backup file extensions (.bak, .old, .tmp, ~, etc.)\n3. Add file patterns to .htaccess or web.config to block access\n4. Use proper backup procedures that store files outside the web root",
                metadata={
                    "exposed_files": exposed_files,
                    "total_files": len(exposed_files),
                },
            )

    def _test_parameter_fuzzing(self, target: str) -> Generator[Finding, None, None]:
        """Test parameter manipulation for privilege escalation."""
        if not self._config.get("test_param_fuzzing", False):
            return

        base_url = self._normalize_url(target)
        test_endpoints = ["/api/user", "/profile", "/account", "/dashboard"]

        vulnerable_params = []

        for endpoint in test_endpoints:
            if self.is_cancelled():
                return

            base_endpoint_url = self._build_url(base_url, endpoint)

            # Test each parameter pattern
            for param_name, param_value in self.PARAM_FUZZ_PATTERNS:
                test_url = f"{base_endpoint_url}?{param_name}={param_value}"
                response = self._make_request(test_url)

                if response and response.status_code == 200:
                    # Look for elevated access indicators
                    content_lower = response.text.lower()
                    if any(
                        keyword in content_lower
                        for keyword in ["admin", "privilege", "elevated", "role"]
                    ):
                        vulnerable_params.append(
                            {
                                "url": test_url,
                                "endpoint": endpoint,
                                "parameter": param_name,
                                "value": param_value,
                            }
                        )

                time.sleep(self._delay_between_requests)

        # Yield single consolidated finding if vulnerabilities found
        if vulnerable_params:
            unique_params = list(set([p["parameter"] for p in vulnerable_params]))
            param_details = "\n".join(
                [
                    f"- {p['parameter']}={p['value']} on {p['endpoint']}"
                    for p in vulnerable_params
                ]
            )
            urls_list = "\n".join([f"  {p['url']}" for p in vulnerable_params[:5]])
            if len(vulnerable_params) > 5:
                urls_list += f"\n  ... and {len(vulnerable_params) - 5} more"

            yield Finding(
                title="Parameter-Based Privilege Escalation Vulnerabilities",
                severity=Severity.CRITICAL,
                description=f"Found {len(vulnerable_params)} parameter manipulation vectors that may grant elevated privileges",
                evidence=f"Vulnerable parameters:\n{param_details}\n\nTest URLs:\n{urls_list}",
                remediation="1. Never trust client-side parameters for access control decisions\n2. Implement server-side authorization checks for all sensitive operations\n3. Use session-based role management instead of parameter-based\n4. Validate and sanitize all user input\n5. Apply principle of least privilege",
                metadata={
                    "vulnerable_parameters": vulnerable_params,
                    "unique_params": unique_params,
                    "total_vectors": len(vulnerable_params),
                },
            )

    def _test_cookie_manipulation(self, target: str) -> Generator[Finding, None, None]:
        """Test cookie manipulation for role elevation."""
        if not self._config.get("test_cookie_manipulation", False):
            return

        base_url = self._normalize_url(target)
        test_paths = ["/", "/dashboard", "/profile", "/account"]

        vulnerable_cookies = []

        for path in test_paths:
            if self.is_cancelled():
                return

            url = self._build_url(base_url, path)

            # Get session first
            session = self._get_session()

            # Test each cookie manipulation
            for cookie_dict in self.COOKIE_MANIPULATION:
                # Add malicious cookies
                for key, value in cookie_dict.items():
                    session.cookies.set(key, value)

                response = self._make_request(url)

                if response and response.status_code == 200:
                    finding = self._analyze_response_content(url, response)
                    if finding:
                        vulnerable_cookies.append(
                            {"url": url, "path": path, "cookies": cookie_dict}
                        )

                # Clear cookies for next test
                session.cookies.clear()
                time.sleep(self._delay_between_requests)

        # Yield single consolidated finding if vulnerabilities found
        if vulnerable_cookies:
            cookie_details = "\n".join(
                [
                    f"- {list(c['cookies'].keys())[0]}={list(c['cookies'].values())[0]} on {c['path']}"
                    for c in vulnerable_cookies
                ]
            )
            urls_list = "\n".join([f"  {c['url']}" for c in vulnerable_cookies[:5]])
            if len(vulnerable_cookies) > 5:
                urls_list += f"\n  ... and {len(vulnerable_cookies) - 5} more"

            yield Finding(
                title="Cookie-Based Privilege Escalation Vulnerabilities",
                severity=Severity.CRITICAL,
                description=f"Found {len(vulnerable_cookies)} cookie manipulation vectors that grant elevated access",
                evidence=f"Vulnerable cookies:\n{cookie_details}\n\nAffected URLs:\n{urls_list}",
                remediation="1. Never trust client-side cookies for authorization decisions\n2. Use secure, server-side session management\n3. Implement proper authentication tokens (JWT with signing)\n4. Set HttpOnly and Secure flags on all cookies\n5. Validate user permissions on every request server-side",
                metadata={
                    "vulnerable_cookies": vulnerable_cookies,
                    "total_vectors": len(vulnerable_cookies),
                },
            )

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute broken access control attack against the target.

        Enhanced workflow:
        1. DNS resolution and host availability check
        2. Website crawling to discover URLs
        3. URL scoring to prioritize testing
        4. Protected path testing with noise filtering
        5. Path traversal testing
        6. IDOR testing

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
            description="Starting enhanced scan for broken access control vulnerabilities with crawling and ML-like URL scoring",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Pre-flight checks: DNS and host availability
            parsed = urlparse(
                target if target.startswith("http") else f"http://{target}"
            )
            hostname = parsed.hostname or parsed.path.split("/")[0]
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            # Check DNS resolution
            ip_address = self._check_dns_resolution(hostname)
            if not ip_address:
                yield Finding(
                    title="DNS Resolution Failed",
                    severity=Severity.CRITICAL,
                    description=f"Unable to resolve hostname '{hostname}' to IP address",
                    evidence=f"Tried system DNS and fallback DNS servers: {', '.join(self.FALLBACK_DNS_SERVERS[:3])}",
                    remediation="Verify the target hostname is correct and accessible",
                    metadata={"hostname": hostname},
                )
                return

            yield Finding(
                title="DNS Resolution Successful",
                severity=Severity.INFO,
                description=f"Hostname '{hostname}' resolved to {ip_address}",
                evidence=f"IP: {ip_address}",
                remediation="N/A - Informational",
                metadata={"hostname": hostname, "ip": ip_address},
            )

            # Check host availability
            if not self._check_host_availability(hostname, port):
                yield Finding(
                    title="Host Unreachable",
                    severity=Severity.HIGH,
                    description=f"Unable to connect to {hostname}:{port}",
                    evidence=f"Connection attempt to {hostname}:{port} failed",
                    remediation="Verify the target is online and the port is correct",
                    metadata={"hostname": hostname, "port": port},
                )
                return

            yield Finding(
                title="Host Reachable",
                severity=Severity.INFO,
                description=f"Successfully connected to {hostname}:{port}",
                evidence="Host is online and accepting connections",
                remediation="N/A - Informational",
                metadata={"hostname": hostname, "port": port},
            )

            # Test 1: Protected paths with crawling and scoring (0-25%)
            yield from self._test_protected_paths(target)

            # Test 2: Path traversal (25-40%)
            yield from self._test_path_traversal(target)

            # Test 3: IDOR (40-55%)
            yield from self._test_idor(target)

            # Aggressive tests (55-100%)
            if self._config.get("test_http_methods", False):
                yield from self._test_http_method_bypass(target)

            if self._config.get("test_header_bypass", False):
                yield from self._test_header_bypass(target)

            if self._config.get("test_forced_browsing", False):
                yield from self._test_forced_browsing(target)

            if self._config.get("test_param_fuzzing", False):
                yield from self._test_parameter_fuzzing(target)

            if self._config.get("test_cookie_manipulation", False):
                yield from self._test_cookie_manipulation(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        # Summary of discovered URLs
        if self._discovered_urls:
            # Prepare evidence with all crawled URLs and scores
            evidence_parts = [
                f"Crawled {len(self._crawled_urls)} pages and discovered {len(self._discovered_urls)} total URLs\n",
                f"Found {len(self._scored_urls)} potentially sensitive URLs (score > 30)\n",
            ]

            # Add top scored URLs
            if self._scored_urls:
                evidence_parts.append(
                    "\n=== Top Scored URLs (Most Likely Sensitive) ==="
                )
                for url, score in self._scored_urls[:10]:
                    evidence_parts.append(f"- [{score:.1f}] {url}")
                if len(self._scored_urls) > 10:
                    evidence_parts.append(
                        f"  ... and {len(self._scored_urls) - 10} more high-scoring URLs"
                    )

            # Add all crawled URLs
            evidence_parts.append("\n=== All Crawled URLs ===")
            sorted_crawled = sorted(self._crawled_urls)
            for url in sorted_crawled[:50]:
                evidence_parts.append(f"- {url}")
            if len(sorted_crawled) > 50:
                evidence_parts.append(
                    f"  ... and {len(sorted_crawled) - 50} more crawled URLs"
                )

            # Add all discovered URLs (that weren't necessarily crawled)
            non_crawled = self._discovered_urls - self._crawled_urls
            if non_crawled:
                evidence_parts.append(
                    "\n=== Additional Discovered URLs (Not Crawled) ==="
                )
                sorted_discovered = sorted(non_crawled)
                for url in sorted_discovered[:30]:
                    evidence_parts.append(f"- {url}")
                if len(sorted_discovered) > 30:
                    evidence_parts.append(
                        f"  ... and {len(sorted_discovered) - 30} more discovered URLs"
                    )

            yield Finding(
                title="URL Discovery Summary",
                severity=Severity.INFO,
                description=f"Website crawling completed: discovered {len(self._discovered_urls)} URLs, "
                f"crawled {len(self._crawled_urls)} pages, "
                f"identified {len(self._scored_urls)} potentially sensitive endpoints",
                evidence="\n".join(evidence_parts),
                remediation="N/A - Informational",
                metadata={
                    "total_discovered": len(self._discovered_urls),
                    "total_crawled": len(self._crawled_urls),
                    "high_score_count": len(self._scored_urls),
                    "crawled_urls": list(self._crawled_urls),
                    "discovered_urls": list(self._discovered_urls),
                    "scored_urls": [(url, score) for url, score in self._scored_urls],
                },
            )

        yield Finding(
            title="Broken Access Control Scan Completed",
            severity=Severity.INFO,
            description="Completed comprehensive scan for broken access control vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
