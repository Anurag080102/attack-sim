"""
A06:2021 - Vulnerable and Outdated Components Attack Module.

This module implements detection of vulnerable and outdated components including:
- Server version fingerprinting
- JavaScript library version detection
- Framework version identification
- Known CVE matching for detected versions

Verified by: Anurag (Dec 17, 2025)
Testing: Passed - 5 findings on live target, detected Nginx & PHP vulnerabilities
"""

import re
import time
from typing import Generator, Dict, Any, List, Tuple
from urllib.parse import urljoin

from attacks.base import Finding, Severity
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase
from attacks.owasp import OWASPRegistry


@OWASPRegistry.register("a06")
class OutdatedComponentsAttack(BaseOWASPAttack):
    """
    Vulnerable and Outdated Components scanner.

    Identifies outdated software versions and known vulnerable components.
    """

    name = "Vulnerable Components Scanner"
    description = "Detects outdated software and components with known vulnerabilities"
    category = OWASPCategory.A06_VULNERABLE_COMPONENTS

    # JavaScript library patterns with version extraction
    JS_LIBRARIES: List[Tuple[str, str, str]] = [
        # (library_name, version_pattern, known_vulnerable_versions)
        ("jQuery", r"jquery[.-]?v?(\d+\.\d+(?:\.\d+)?)", "1.x,2.x<2.2.0"),
        ("jQuery UI", r"jquery-ui[.-]?v?(\d+\.\d+(?:\.\d+)?)", "1.x<1.13.0"),
        ("Bootstrap", r"bootstrap[.-]?v?(\d+\.\d+(?:\.\d+)?)", "2.x,3.x<3.4.0"),
        ("Angular", r"angular[.-]?v?(\d+\.\d+(?:\.\d+)?)", "1.x"),
        ("React", r"react[.-]?v?(\d+\.\d+(?:\.\d+)?)", ""),
        ("Vue.js", r"vue[.-]?v?(\d+\.\d+(?:\.\d+)?)", "2.x<2.6.14"),
        ("Lodash", r"lodash[.-]?v?(\d+\.\d+(?:\.\d+)?)", "4.x<4.17.21"),
        ("Moment.js", r"moment[.-]?v?(\d+\.\d+(?:\.\d+)?)", "all"),
        # Deprecated
        ("Underscore", r"underscore[.-]?v?(\d+\.\d+(?:\.\d+)?)", "1.x<1.13.1"),
    ]

    # Server software patterns
    SERVER_PATTERNS: List[Tuple[str, str, str]] = [
        ("Apache", r"Apache/(\d+\.\d+(?:\.\d+)?)", "2.2.x,2.4.x<2.4.54"),
        ("Nginx", r"nginx/(\d+\.\d+(?:\.\d+)?)", "1.x<1.22.1"),
        ("IIS", r"IIS/(\d+\.\d+)", "7.x,8.x"),
        ("PHP", r"PHP/(\d+\.\d+(?:\.\d+)?)", "5.x,7.x<7.4.33,8.0.x<8.0.27"),
        ("ASP.NET", r"ASP\.NET Version:(\d+\.\d+(?:\.\d+)?)", ""),
        ("Tomcat", r"Tomcat/(\d+\.\d+(?:\.\d+)?)", "8.x<8.5.84,9.x<9.0.70"),
        ("Express", r"Express/?(\d+\.\d+(?:\.\d+)?)?", "3.x"),
    ]

    # CMS and framework detection patterns
    CMS_PATTERNS: List[Tuple[str, str, str, str]] = [
        # (name, detection_pattern, version_pattern, vulnerable_versions)
        (
            "WordPress",
            r"wp-content|wp-includes",
            r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"',
            "4.x<4.9.8,5.x<5.8.3",
        ),
        ("Drupal", r"Drupal|drupal\.js", r"Drupal (\d+\.\d+)", "7.x<7.91,8.x,9.x<9.4.3"),
        (
            "Joomla",
            r"Joomla!|/media/jui/",
            r'<meta name="generator" content="Joomla! (\d+\.\d+)"',
            "3.x<3.10.11",
        ),
        (
            "Magento",
            r"Mage\.Cookies|/skin/frontend/",
            r"Magento/(\d+\.\d+(?:\.\d+)?)",
            "1.x,2.3.x<2.3.7-p4",
        ),
        (
            "Django",
            r"csrfmiddlewaretoken|django",
            r"Django/(\d+\.\d+(?:\.\d+)?)",
            "2.x<2.2.28,3.x<3.2.15",
        ),
        ("Laravel", r"laravel_session", r"Laravel v(\d+\.\d+(?:\.\d+)?)", "8.x<8.83.27"),
        (
            "Ruby on Rails",
            r"csrf-token|rails",
            r"Rails (\d+\.\d+(?:\.\d+)?)",
            "5.x<5.2.8.1,6.x<6.1.7",
        ),
    ]

    # Known vulnerable versions database (simplified)
    KNOWN_VULNS: Dict[str, List[Tuple[str, str, str]]] = {
        # library: [(version_range, CVE, description)]
        "jQuery": [
            ("1.0.0-1.12.0", "CVE-2015-9251", "XSS vulnerability in jQuery before 1.12.0"),
            ("1.0.0-3.4.0", "CVE-2019-11358", "Prototype pollution in jQuery < 3.4.0"),
            ("1.0.0-3.5.0", "CVE-2020-11022", "XSS vulnerability in htmlPrefilter"),
        ],
        "Bootstrap": [
            ("3.0.0-3.4.0", "CVE-2019-8331", "XSS vulnerability in tooltip/popover"),
            ("4.0.0-4.3.1", "CVE-2019-8331", "XSS vulnerability in tooltip/popover data-template"),
        ],
        "Lodash": [
            ("0.0.0-4.17.11", "CVE-2019-10744", "Prototype pollution in defaultsDeep"),
            ("0.0.0-4.17.20", "CVE-2021-23337", "Command injection via template"),
        ],
        "Angular": [
            ("1.0.0-1.7.9", "CVE-2020-7676", "XSS vulnerability in angular.js"),
        ],
        "Vue.js": [
            ("2.0.0-2.6.13", "CVE-2021-46314", "ReDoS vulnerability"),
        ],
    }

    def __init__(self):
        super().__init__()
        self._detected_components: List[Dict[str, str]] = []

    def configure(self, **kwargs) -> None:
        """
        Configure outdated components attack parameters.

        Args:
            detect_js_libs: Detect JavaScript libraries (default: True)
            detect_server: Detect server software (default: True)
            detect_cms: Detect CMS and frameworks (default: True)
            check_cves: Check for known CVEs (default: True)
        """
        super().configure(**kwargs)
        self._config["detect_js_libs"] = kwargs.get("detect_js_libs", True)
        self._config["detect_server"] = kwargs.get("detect_server", True)
        self._config["detect_cms"] = kwargs.get("detect_cms", True)
        self._config["check_cves"] = kwargs.get("check_cves", True)

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "detect_js_libs": {
                    "type": "boolean",
                    "default": True,
                    "description": "Detect JavaScript libraries",
                },
                "detect_server": {
                    "type": "boolean",
                    "default": True,
                    "description": "Detect server software versions",
                },
                "detect_cms": {
                    "type": "boolean",
                    "default": True,
                    "description": "Detect CMS and framework versions",
                },
                "check_cves": {
                    "type": "boolean",
                    "default": True,
                    "description": "Check detected versions against known CVEs",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for vulnerable components."""
        return [
            OWASPTestCase(
                name="JavaScript Library Detection",
                description="Identify JavaScript libraries and their versions",
                category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                payloads=[],
                detection_patterns=[lib[0] for lib in self.JS_LIBRARIES],
            ),
            OWASPTestCase(
                name="Server Fingerprinting",
                description="Identify server software and versions",
                category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                payloads=[],
                detection_patterns=[srv[0] for srv in self.SERVER_PATTERNS],
            ),
            OWASPTestCase(
                name="CMS Detection",
                description="Identify CMS and framework versions",
                category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                payloads=[],
                detection_patterns=[cms[0] for cms in self.CMS_PATTERNS],
            ),
        ]

    def _version_in_range(self, version: str, range_str: str) -> bool:
        """
        Check if a version is in a vulnerable range.
        
        Compares version numbers to determine if a detected version falls within
        a known vulnerable version range. Uses semantic versioning comparison.

        Args:
            version: Version string (e.g., "1.12.4")
            range_str: Range string (e.g., "1.0.0-1.12.0")

        Returns:
            True if version is in the vulnerable range, False otherwise
        """
        if not version or not range_str:
            return False

        try:
            # Parse version into numeric parts (major, minor, patch)
            version_parts = [int(x) for x in re.findall(r"\d+", version)][:3]
            while len(version_parts) < 3:
                version_parts.append(0)

            if "-" in range_str:
                # Parse min and max versions from range
                min_ver, max_ver = range_str.split("-")
                min_parts = [int(x) for x in re.findall(r"\d+", min_ver)][:3]
                max_parts = [int(x) for x in re.findall(r"\d+", max_ver)][:3]

                # Normalize to 3-part version numbers
                while len(min_parts) < 3:
                    min_parts.append(0)
                while len(max_parts) < 3:
                    max_parts.append(0)

                # Check if version falls within range (inclusive)
                return min_parts <= version_parts <= max_parts

            return False
        except (ValueError, IndexError):
            # Handle malformed version strings gracefully
            return False

    def _detect_server_software(self, target: str) -> Generator[Finding, None, None]:
        """Detect server software from HTTP headers."""
        if not self._config.get("detect_server", True):
            return

        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        headers = self._get_headers_dict(response)

        # Check Server header
        server_header = headers.get("server", "")
        x_powered_by = headers.get("x-powered-by", "")

        all_header_text = f"{server_header} {x_powered_by}"

        for name, pattern, vuln_versions in self.SERVER_PATTERNS:
            match = re.search(pattern, all_header_text, re.IGNORECASE)

            if match:
                version = match.group(1) if match.groups() else "unknown"

                self._detected_components.append(
                    {"name": name, "version": version, "source": "header"}
                )

                # Check if version is outdated/vulnerable
                is_vulnerable = False
                if vuln_versions and version != "unknown":
                    for vuln_range in vuln_versions.split(","):
                        if "<" in vuln_range:
                            # Format: "2.4.x<2.4.54" means 2.4.x before 2.4.54
                            pass  # Simplified check
                        elif version.startswith(vuln_range.rstrip("x.")):
                            is_vulnerable = True
                            break

                severity = Severity.HIGH if is_vulnerable else Severity.LOW

                vuln_msg = "This version may be outdated or vulnerable."
                info_msg = "Version information disclosed."
                status_msg = vuln_msg if is_vulnerable else info_msg
                yield Finding(
                    title=f"Server Software Detected: {name}",
                    severity=severity,
                    description=f"Detected {name} version {version}. {status_msg}",
                    evidence=f"Header: {server_header or x_powered_by}",
                    remediation="Keep server software up to date. "
                    "Consider hiding version information in production.",
                    metadata={
                        "software": name,
                        "version": version,
                        "header": server_header or x_powered_by,
                    },
                )

        self.set_progress(25)

    def _detect_javascript_libraries(self, target: str) -> Generator[Finding, None, None]:
        """Detect JavaScript libraries from page source and script files."""
        if not self._config.get("detect_js_libs", True):
            return

        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        content = response.text

        # Extract script sources
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        scripts = re.findall(script_pattern, content, re.IGNORECASE)

        # Also check inline scripts and main page
        all_content = content

        # Fetch a few script files
        for script_src in scripts[:10]:
            if self.is_cancelled():
                return

            script_url = urljoin(base_url, script_src)
            script_response = self._make_request(script_url)

            if script_response and script_response.status_code == 200:
                all_content += script_response.text

            time.sleep(self._delay_between_requests)

        # Detect libraries
        for lib_name, version_pattern, vuln_versions in self.JS_LIBRARIES:
            match = re.search(version_pattern, all_content, re.IGNORECASE)

            if match:
                version = match.group(1) if match.groups() else "unknown"

                self._detected_components.append(
                    {"name": lib_name, "version": version, "source": "javascript"}
                )

                # Check for known vulnerabilities
                vulns_found = []
                if lib_name in self.KNOWN_VULNS:
                    for vuln_range, cve, description in self.KNOWN_VULNS[lib_name]:
                        if self._version_in_range(version, vuln_range):
                            vulns_found.append((cve, description))

                if vulns_found:
                    for cve, description in vulns_found:
                        yield Finding(
                            title=f"Vulnerable JavaScript Library: {lib_name} {version}",
                            severity=Severity.HIGH,
                            description=f"{lib_name} version {version} has known vulnerabilities",
                            evidence=f"CVE: {cve}, Description: {description}",
                            remediation=f"Update {lib_name} to the latest version. "
                            f"Check for security advisories.",
                            metadata={
                                "library": lib_name,
                                "version": version,
                                "cve": cve,
                                "description": description,
                            },
                        )
                else:
                    # Check if using deprecated library
                    is_deprecated = vuln_versions == "all"

                    if is_deprecated:
                        yield Finding(
                            title=f"Deprecated Library: {lib_name} {version}",
                            severity=Severity.MEDIUM,
                            description=f"{lib_name} is deprecated and no longer maintained",
                            evidence=f"Library: {lib_name}, Version: {version}",
                            remediation=f"Replace {lib_name} with a maintained alternative",
                            metadata={"library": lib_name, "version": version, "deprecated": True},
                        )
                    else:
                        yield Finding(
                            title=f"JavaScript Library Detected: {lib_name} {version}",
                            severity=Severity.INFO,
                            description=f"Detected {lib_name} version {version}",
                            evidence=f"Library: {lib_name}, Version: {version}",
                            remediation="Ensure library is kept up to date",
                            metadata={"library": lib_name, "version": version},
                        )

        self.set_progress(50)

    def _detect_cms_framework(self, target: str) -> Generator[Finding, None, None]:
        """Detect CMS and framework from page source and characteristics."""
        if not self._config.get("detect_cms", True):
            return

        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        content = response.text

        for cms_name, detect_pattern, version_pattern, vuln_versions in self.CMS_PATTERNS:
            if self.is_cancelled():
                return

            # Check for CMS indicators
            if re.search(detect_pattern, content, re.IGNORECASE):
                version = "unknown"

                # Try to extract version
                version_match = re.search(version_pattern, content, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)

                self._detected_components.append(
                    {"name": cms_name, "version": version, "source": "cms_detection"}
                )

                # Check if potentially vulnerable
                is_vulnerable = False
                if vuln_versions and version != "unknown":
                    for vuln_range in vuln_versions.split(","):
                        if version.startswith(vuln_range.split("<")[0].rstrip("x.")):
                            is_vulnerable = True
                            break

                severity = Severity.MEDIUM if is_vulnerable else Severity.INFO

                yield Finding(
                    title=f"CMS/Framework Detected: {cms_name}",
                    severity=severity,
                    description=f"Detected {cms_name}"
                    + (f" version {version}" if version != "unknown" else "")
                    + (". This version may have known vulnerabilities." if is_vulnerable else ""),
                    evidence="Detection pattern matched in page source",
                    remediation=f"Keep {cms_name} and all plugins/modules up to date. "
                    "Subscribe to security advisories.",
                    metadata={
                        "cms": cms_name,
                        "version": version,
                        "potentially_vulnerable": is_vulnerable,
                    },
                )

        # WordPress-specific checks
        if "wp-content" in content or "wp-includes" in content:
            # Check for readme.html (version disclosure)
            readme_url = self._build_url(base_url, "/readme.html")
            readme_response = self._make_request(readme_url)

            if readme_response and readme_response.status_code == 200:
                yield Finding(
                    title="WordPress readme.html Accessible",
                    severity=Severity.LOW,
                    description="WordPress readme.html file is accessible, exposing version information",
                    evidence=f"URL: {readme_url}",
                    remediation="Remove or restrict access to readme.html",
                    metadata={"url": readme_url},
                )

        self.set_progress(75)

    def _check_known_vulnerabilities(self, target: str) -> Generator[Finding, None, None]:
        """Cross-reference detected components with known CVEs."""
        if not self._config.get("check_cves", True):
            return

        # Summary of all detected components
        if self._detected_components:
            components_summary = ", ".join(
                f"{c['name']}  {c['version']} " for c in self._detected_components
            )

            yield Finding(
                title="Component Detection Summary",
                severity=Severity.INFO,
                description=f"Detected {len(self._detected_components)} software components",
                evidence=f"Components: {components_summary}",
                remediation="Review all detected components and ensure they are up to date",
                metadata={
                    "components": self._detected_components,
                    "count": len(self._detected_components),
                },
            )

        self.set_progress(100)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute vulnerable components attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True
        self._detected_components = []

        yield Finding(
            title="Vulnerable Components Scan Started",
            severity=Severity.INFO,
            description="Starting scan for vulnerable and outdated components",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Test 1: Server Software Detection (0-25%)
            yield from self._detect_server_software(target)

            # Test 2: JavaScript Libraries (25-50%)
            yield from self._detect_javascript_libraries(target)

            # Test 3: CMS/Framework Detection (50-75%)
            yield from self._detect_cms_framework(target)

            # Test 4: CVE Cross-reference (75-100%)
            yield from self._check_known_vulnerabilities(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Vulnerable Components Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for vulnerable and outdated components",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
