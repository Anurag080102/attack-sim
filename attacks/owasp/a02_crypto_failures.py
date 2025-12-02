"""
A02:2021 - Cryptographic Failures Attack Module.

This module implements detection of cryptographic vulnerabilities including:
- Weak SSL/TLS configurations
- Missing HTTPS enforcement
- Weak cipher suites
- Certificate validation issues
- Sensitive data exposure through insecure transmission
"""

import re
import ssl
import socket
import time
from typing import Generator, Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from attacks.base import Finding, Severity
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase
from attacks.owasp import OWASPRegistry


@OWASPRegistry.register("a02")
class CryptographicFailuresAttack(BaseOWASPAttack):
    """
    Cryptographic Failures vulnerability scanner.

    Tests for weak cryptographic implementations, insecure protocols,
    and sensitive data exposure.
    """

    name = "Cryptographic Failures Scanner"
    description = "Detects cryptographic vulnerabilities including weak SSL/TLS and cipher suites"
    category = OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES

    # Weak cipher suites that should be flagged
    WEAK_CIPHERS = [
        "RC4",
        "DES",
        "3DES",
        "MD5",
        "NULL",
        "EXPORT",
        "anon",
        "ADH",
        "AECDH",
    ]

    # Deprecated/insecure TLS versions
    DEPRECATED_PROTOCOLS = [
        ssl.PROTOCOL_SSLv23,  # May negotiate to SSLv3
    ]

    # Insecure protocol names for reporting
    INSECURE_PROTOCOL_NAMES = {
        "SSLv2": "SSL 2.0 - Severely broken",
        "SSLv3": "SSL 3.0 - Vulnerable to POODLE",
        "TLSv1.0": "TLS 1.0 - Deprecated, vulnerable to BEAST",
        "TLSv1.1": "TLS 1.1 - Deprecated",
    }

    # Headers that indicate secure transport
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "HTTP Strict Transport Security (HSTS)",
            "severity": Severity.MEDIUM,
            "description": "HSTS header is missing, site vulnerable to SSL stripping attacks",
        },
    }

    # Sensitive data patterns that shouldn't appear in URLs or unencrypted
    # responses
    SENSITIVE_DATA_PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']?[\w@#$%^&*]+', "Password in response"),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]+', "API key in response"),
        (r'secret["\']?\s*[:=]\s*["\']?[\w-]+', "Secret in response"),
        (r'token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "Token in response"),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private key exposed"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email addresses"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
        (r"\b\d{16}\b", "Possible credit card number"),
    ]

    def __init__(self):
        super().__init__()
        self._ssl_context: Optional[ssl.SSLContext] = None

    def configure(self, **kwargs) -> None:
        """
        Configure cryptographic failures attack parameters.

        Args:
            check_ssl: Whether to check SSL/TLS configuration (default: True)
            check_headers: Whether to check security headers (default: True)
            check_sensitive_data: Whether to scan for sensitive data exposure (default: True)
            ssl_timeout: Timeout for SSL connections (default: 5)
        """
        super().configure(**kwargs)
        self._config["check_ssl"] = kwargs.get("check_ssl", True)
        self._config["check_headers"] = kwargs.get("check_headers", True)
        self._config["check_sensitive_data"] = kwargs.get("check_sensitive_data", True)
        self._config["ssl_timeout"] = kwargs.get("ssl_timeout", 5)

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update(
            {
                "check_ssl": {
                    "type": "boolean",
                    "default": True,
                    "description": "Check SSL/TLS configuration",
                },
                "check_headers": {
                    "type": "boolean",
                    "default": True,
                    "description": "Check security headers",
                },
                "check_sensitive_data": {
                    "type": "boolean",
                    "default": True,
                    "description": "Scan for sensitive data exposure",
                },
                "ssl_timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "SSL connection timeout in seconds",
                },
            }
        )
        return options

    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for cryptographic failures."""
        return [
            OWASPTestCase(
                name="SSL/TLS Configuration",
                description="Test SSL/TLS protocols and cipher suites",
                category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                payloads=[],
                detection_patterns=self.WEAK_CIPHERS,
            ),
            OWASPTestCase(
                name="Security Headers",
                description="Check for missing security headers",
                category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                payloads=[],
                detection_patterns=list(self.SECURITY_HEADERS.keys()),
            ),
            OWASPTestCase(
                name="Sensitive Data Exposure",
                description="Scan for exposed sensitive data",
                category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                payloads=[],
                detection_patterns=[p[0] for p in self.SENSITIVE_DATA_PATTERNS],
            ),
        ]

    def _get_ssl_info(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """
        Get SSL/TLS information from a host.

        Args:
            hostname: Target hostname
            port: Target port (default: 443)

        Returns:
            Dictionary with SSL info or None if connection failed
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self._config.get("ssl_timeout", 5)
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    return {
                        "certificate": cert,
                        "cipher": cipher,
                        "version": version,
                        "cipher_name": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                    }
        except (socket.error, ssl.SSLError, OSError):
            return None

    def _check_deprecated_protocols(self, hostname: str, port: int = 443) -> List[Tuple[str, bool]]:
        """
        Check which deprecated protocols are supported.

        Returns:
            List of (protocol_name, is_supported) tuples
        """
        results = []
        protocols_to_test = [
            ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None),
        ]

        for proto_name, proto_version in protocols_to_test:
            if proto_version is None:
                continue

            try:
                context = ssl.SSLContext(proto_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection(
                    (hostname, port), timeout=self._config.get("ssl_timeout", 5)
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        results.append((proto_name, True))
            except (socket.error, ssl.SSLError, OSError):
                results.append((proto_name, False))

        return results

    def _test_ssl_configuration(self, target: str) -> Generator[Finding, None, None]:
        """Test SSL/TLS configuration."""
        if not self._config.get("check_ssl", True):
            return

        parsed = urlparse(self._normalize_url(target))
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not hostname:
            return

        # Check if HTTPS is available
        ssl_info = self._get_ssl_info(hostname, 443 if port == 80 else port)

        if ssl_info is None and parsed.scheme == "http":
            # Target uses HTTP, check if HTTPS is available at all
            ssl_info_443 = self._get_ssl_info(hostname, 443)

            if ssl_info_443 is None:
                yield Finding(
                    title="No HTTPS Available",
                    severity=Severity.HIGH,
                    description="The target does not appear to support HTTPS. "
                    "All data is transmitted in plain text.",
                    evidence=f"Host: {hostname}, Port 443 not responding to SSL",
                    remediation="Enable HTTPS with a valid SSL/TLS certificate. "
                    "Use TLS 1.2 or higher with strong cipher suites.",
                    metadata={"hostname": hostname},
                )
            else:
                yield Finding(
                    title="HTTP Used Instead of HTTPS",
                    severity=Severity.MEDIUM,
                    description="The target is using HTTP but HTTPS is available. "
                    "Traffic should be redirected to HTTPS.",
                    evidence=f"HTTP: {target}, HTTPS available on port 443",
                    remediation="Redirect all HTTP traffic to HTTPS. "
                    "Implement HSTS to prevent downgrade attacks.",
                    metadata={"hostname": hostname},
                )
                ssl_info = ssl_info_443

        if ssl_info:
            # Check cipher strength
            cipher_name = ssl_info.get("cipher_name", "")
            cipher_bits = ssl_info.get("cipher_bits", 0)

            # Check for weak ciphers
            for weak_cipher in self.WEAK_CIPHERS:
                if weak_cipher.upper() in cipher_name.upper():
                    yield Finding(
                        title="Weak Cipher Suite in Use",
                        severity=Severity.HIGH,
                        description=f"The server is using a weak cipher suite: {cipher_name}",
                        evidence=f"Cipher: {cipher_name}, Bits: {cipher_bits}",
                        remediation="Configure the server to use only strong cipher suites. "
                        "Disable RC4, DES, 3DES, MD5, NULL, EXPORT, and anonymous ciphers.",
                        metadata={
                            "cipher": cipher_name,
                            "bits": cipher_bits,
                            "weak_cipher_matched": weak_cipher,
                        },
                    )
                    break

            # Check cipher bit strength
            if cipher_bits and cipher_bits < 128:
                yield Finding(
                    title="Weak Cipher Key Length",
                    severity=Severity.MEDIUM,
                    description=f"The cipher key length is too short: {cipher_bits} bits",
                    evidence=f"Cipher: {cipher_name}, Bits: {cipher_bits}",
                    remediation="Use ciphers with at least 128-bit key length. "
                    "256-bit AES is recommended.",
                    metadata={"cipher": cipher_name, "bits": cipher_bits},
                )

            # Check TLS version
            version = ssl_info.get("version", "")
            if version in self.INSECURE_PROTOCOL_NAMES:
                yield Finding(
                    title="Deprecated TLS/SSL Version",
                    severity=Severity.MEDIUM,
                    description=f"Server supports deprecated protocol: {version}",
                    evidence=f"Protocol: {version} - {self.INSECURE_PROTOCOL_NAMES[version]}",
                    remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2 or TLS 1.3 only.",
                    metadata={"version": version},
                )

        # Check for deprecated protocol support
        deprecated = self._check_deprecated_protocols(hostname, 443 if port == 80 else port)

        for proto_name, is_supported in deprecated:
            if is_supported:
                yield Finding(
                    title=f"Deprecated Protocol Supported: {proto_name}",
                    severity=Severity.MEDIUM,
                    description=f"The server still supports deprecated protocol {proto_name}",
                    evidence=f"Protocol: {proto_name} - {self.INSECURE_PROTOCOL_NAMES.get(proto_name, 'Deprecated')}",
                    remediation="Disable support for TLS 1.0 and TLS 1.1. "
                    "Only allow TLS 1.2 and TLS 1.3.",
                    metadata={"protocol": proto_name},
                )

        self.set_progress(33)

    def _test_security_headers(self, target: str) -> Generator[Finding, None, None]:
        """Test for missing security headers."""
        if not self._config.get("check_headers", True):
            return

        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        headers = self._get_headers_dict(response)

        # Check for HSTS
        if "strict-transport-security" not in headers:
            parsed = urlparse(base_url)
            if parsed.scheme == "https":
                yield Finding(
                    title="Missing HSTS Header",
                    severity=Severity.MEDIUM,
                    description="HTTP Strict Transport Security header is not set. "
                    "The site is vulnerable to SSL stripping attacks.",
                    evidence=f"URL: {base_url}, Missing: Strict-Transport-Security",
                    remediation="Add the Strict-Transport-Security header with a long max-age. "
                    "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    metadata={"url": base_url},
                )
        else:
            hsts_value = headers.get("strict-transport-security", "")
            # Check if max-age is too short
            max_age_match = re.search(r"max-age=(\d+)", hsts_value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 15768000:  # Less than 6 months
                    yield Finding(
                        title="HSTS Max-Age Too Short",
                        severity=Severity.LOW,
                        description=f"HSTS max-age is set to {max_age} seconds, which may be too short",
                        evidence=f"Header: {hsts_value}",
                        remediation="Set max-age to at least 15768000 (6 months) or 31536000 (1 year)",
                        metadata={"hsts_value": hsts_value, "max_age": max_age},
                    )

        # Check for secure cookie attributes on Set-Cookie headers
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            if "secure" not in set_cookie.lower():
                yield Finding(
                    title="Cookie Missing Secure Flag",
                    severity=Severity.MEDIUM,
                    description="Cookies are being set without the Secure flag, "
                    "allowing transmission over unencrypted connections",
                    evidence=f"Set-Cookie: {set_cookie[:100]}...",
                    remediation="Add the Secure flag to all cookies containing sensitive data",
                    metadata={"cookie_header": set_cookie},
                )

        self.set_progress(66)

    def _test_sensitive_data_exposure(self, target: str) -> Generator[Finding, None, None]:
        """Scan for sensitive data exposure in responses."""
        if not self._config.get("check_sensitive_data", True):
            return

        base_url = self._normalize_url(target)

        # Test main page and common endpoints
        endpoints = ["", "/api", "/api/config", "/config", "/debug", "/info", "/.env"]

        for endpoint in endpoints:
            if self.is_cancelled():
                break

            url = self._build_url(base_url, endpoint) if endpoint else base_url
            response = self._make_request(url)

            if not response or response.status_code != 200:
                continue

            content = response.text

            for pattern, description in self.SENSITIVE_DATA_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)

                if matches:
                    # Limit the number of matches shown
                    sample_matches = matches[:3]

                    # Redact sensitive data in evidence
                    redacted_matches = []
                    for match in sample_matches:
                        if len(match) > 10:
                            redacted_matches.append(match[:5] + "..." + match[-3:])
                        else:
                            redacted_matches.append("***REDACTED***")

                    yield Finding(
                        title=f"Sensitive Data Exposure: {description}",
                        severity=Severity.HIGH,
                        description=f"Potentially sensitive data found in response: {description}",
                        evidence=f"URL: {url}, Found {len(matches)} occurrence(s), "
                        f"Sample (redacted): {redacted_matches}",
                        remediation="Remove sensitive data from responses. "
                        "Use proper access controls and encryption for sensitive data.",
                        metadata={
                            "url": url,
                            "pattern_type": description,
                            "match_count": len(matches),
                        },
                    )

            time.sleep(self._delay_between_requests)

        self.set_progress(100)

    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute cryptographic failures attack against the target.

        Args:
            target: Target URL

        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True

        yield Finding(
            title="Cryptographic Failures Scan Started",
            severity=Severity.INFO,
            description="Starting scan for cryptographic vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )

        try:
            # Test 1: SSL/TLS Configuration (0-33%)
            yield from self._test_ssl_configuration(target)

            # Test 2: Security Headers (33-66%)
            yield from self._test_security_headers(target)

            # Test 3: Sensitive Data Exposure (66-100%)
            yield from self._test_sensitive_data_exposure(target)

        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()

        yield Finding(
            title="Cryptographic Failures Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for cryptographic vulnerabilities",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target},
        )
