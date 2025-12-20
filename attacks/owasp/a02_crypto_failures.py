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
import httpx
from datetime import datetime
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

    # AGGRESSIVE: All weak cipher suites and vulnerable patterns
    WEAK_CIPHERS = [
        "RC4", "RC2", "RC5",  # Stream ciphers
        "DES", "3DES", "IDEA",  # Weak block ciphers
        "MD5", "MD4", "MD2",  # Weak hashes
        "SHA1",  # Deprecated hash
        "NULL", "EXPORT",  # No encryption
        "anon", "ADH", "AECDH", "aNULL", "eNULL",  # Anonymous
        "CBC",  # Padding oracle vulnerable
        "DHE-RSA", "DHE-DSS",  # Weak DH params possible
        "PSK",  # Pre-shared key (often weak)
        "SRP",  # Secure Remote Password (rarely used correctly)
        "CAMELLIA",  # Not recommended
        "SEED",  # Weak cipher
        "ARIA",  # Less tested
        "GOST",  # Russian standard, not widely trusted
        "40", "56", "128",  # Bit strength indicators for weak keys
    ]

    # Deprecated/insecure TLS versions to test
    DEPRECATED_PROTOCOLS = {
        "SSLv2": getattr(ssl, "PROTOCOL_SSLv2", None),
        "SSLv3": getattr(ssl, "PROTOCOL_SSLv3", None),
        "TLSv1.0": getattr(ssl, "PROTOCOL_TLSv1", None),
        "TLSv1.1": getattr(ssl, "PROTOCOL_TLSv1_1", None),
    }

    # Insecure protocol names for reporting
    INSECURE_PROTOCOL_NAMES = {
        "SSLv2": "SSL 2.0 - Severely broken, multiple vulnerabilities",
        "SSLv3": "SSL 3.0 - Vulnerable to POODLE attack",
        "TLSv1.0": "TLS 1.0 - Deprecated by PCI-DSS, vulnerable to BEAST",
        "TLSv1.1": "TLS 1.1 - Deprecated by major browsers",
        "TLSv1": "TLS 1.0 - Deprecated by PCI-DSS, vulnerable to BEAST",
    }

    # Comprehensive security headers to check (aggressive mode)
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "HTTP Strict Transport Security (HSTS)",
            "severity": Severity.MEDIUM,
            "description": "HSTS header is missing, site vulnerable to SSL stripping attacks",
        },
        "content-security-policy": {
            "name": "Content Security Policy (CSP)",
            "severity": Severity.LOW,
            "description": "CSP header missing, vulnerable to XSS and data injection",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity": Severity.LOW,
            "description": "X-Content-Type-Options missing, vulnerable to MIME sniffing",
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity": Severity.LOW,
            "description": "X-Frame-Options missing, vulnerable to clickjacking",
        },
    }

    # SUPER AGGRESSIVE: Expanded sensitive data patterns (50+ patterns)
    SENSITIVE_DATA_PATTERNS = [
        # Passwords - all variations
        (r'password["\']?\s*[:=]\s*["\']?[\w@#$%^&*]+', "Password in response"),
        (r'passwd["\']?\s*[:=]\s*["\']?[\w@#$%^&*]+', "Password (passwd) in response"),
        (r'pwd["\']?\s*[:=]\s*["\']?[\w@#$%^&*]+', "Password (pwd) in response"),
        (r'pass["\']?\s*[:=]\s*["\']?[\w@#$%^&*]+', "Password (pass) in response"),
        (r'user_password["\']?\s*[:=]\s*["\']?[\w@#$%^&*]+', "User password in response"),
        
        # API Keys - all major providers
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]+', "API key in response"),
        (r'apikey["\']?\s*[:=]\s*["\']?[\w-]+', "API key (apikey) in response"),
        (r'api[_-]?secret["\']?\s*[:=]\s*["\']?[\w-]+', "API secret in response"),
        (r'client[_-]?secret["\']?\s*[:=]\s*["\']?[\w-]+', "Client secret in response"),
        
        # Secrets and tokens
        (r'secret["\']?\s*[:=]\s*["\']?[\w-]+', "Secret in response"),
        (r'secret[_-]?key["\']?\s*[:=]\s*["\']?[\w-]+', "Secret key in response"),
        (r'access[_-]?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "Access token in response"),
        (r'bearer["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "Bearer token in response"),
        (r'token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "Token in response"),
        (r'auth["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "Auth token in response"),
        (r'refresh[_-]?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "Refresh token"),
        (r'session[_-]?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "Session token"),
        (r'csrf[_-]?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "CSRF token"),
        
        # Private keys and certificates
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "RSA private key exposed"),
        (r"-----BEGIN\s+CERTIFICATE-----", "Certificate exposed"),
        (r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", "SSH private key exposed"),
        (r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----", "DSA private key exposed"),
        (r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", "EC private key exposed"),
        (r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----", "PGP private key exposed"),
        
        # PII Data
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email addresses"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
        (r"\b\d{16}\b", "Possible credit card number"),
        (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "Credit card pattern"),
        (r"\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b", "Phone number pattern"),
        
        # Cloud provider keys
        (r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?[A-Z0-9]{20}', "AWS Access Key ID"),
        (r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}', "AWS Secret Key"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'ASIA[0-9A-Z]{16}', "AWS Temporary Access Key"),
        (r'azure[_-]?client[_-]?secret["\']?\s*[:=]', "Azure Client Secret"),
        (r'gcp[_-]?api[_-]?key["\']?\s*[:=]', "GCP API Key"),
        
        # Database connection strings
        (r'mongodb(\+srv)?://[^\s]+', "MongoDB connection string"),
        (r'mysql://[^\s]+', "MySQL connection string"),
        (r'postgres://[^\s]+', "PostgreSQL connection string"),
        (r'redis://[^\s]+', "Redis connection string"),
        (r'jdbc:[^\s]+', "JDBC connection string"),
        (r'Server=.*;Database=.*;User\s+Id=.*', "SQL Server connection string"),
        
        # Third-party service tokens
        (r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}', "Slack token"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth token"),
        (r'ghs_[a-zA-Z0-9]{36}', "GitHub Server token"),
        (r'github_pat_[a-zA-Z0-9_]{82}', "GitHub fine-grained PAT"),
        (r'sk_live_[0-9a-zA-Z]{24}', "Stripe live key"),
        (r'sk_test_[0-9a-zA-Z]{24}', "Stripe test key"),
        (r'pk_live_[0-9a-zA-Z]{24}', "Stripe publishable live key"),
        (r'rk_live_[0-9a-zA-Z]{24}', "Stripe restricted key"),
        (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API key"),
        (r'key-[0-9a-zA-Z]{32}', "Mailgun API key"),
        (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "Google OAuth ID"),
        (r'ya29\.[0-9A-Za-z_-]+', "Google OAuth token"),
        (r'AIza[0-9A-Za-z_-]{35}', "Google API key"),
        
        # JWT tokens
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT token"),
        
        # Environment variables
        (r'DB_PASSWORD\s*=\s*["\']?[\w@#$%^&*]+', "Database password in env"),
        (r'DB_USERNAME\s*=\s*["\']?[\w]+', "Database username in env"),
        (r'DATABASE_URL\s*=\s*["\']?[^\s]+', "Database URL in env"),
        (r'REDIS_URL\s*=\s*["\']?[^\s]+', "Redis URL in env"),
        (r'MAIL_PASSWORD\s*=\s*["\']?[\w@#$%^&*]+', "Mail password in env"),
        (r'SMTP_PASSWORD\s*=\s*["\']?[\w@#$%^&*]+', "SMTP password in env"),
        
        # Encryption keys
        (r'encryption[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=]{32,}', "Encryption key"),
        (r'private[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=]{32,}', "Private key value"),
        (r'master[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=]{32,}', "Master key"),
    ]

    def __init__(self):
        super().__init__()
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._httpx_client: Optional[httpx.Client] = None

    def cleanup(self) -> None:
        """Clean up resources including httpx client."""
        if self._httpx_client:
            try:
                self._httpx_client.close()
            except Exception:
                pass
            self._httpx_client = None
        super().cleanup()

    def _get_httpx_client(self) -> httpx.Client:
        """Get or create httpx client for HTTPS checks."""
        if self._httpx_client is None:
            self._httpx_client = httpx.Client(
                verify=False,  # We're testing SSL, not validating it
                timeout=self._config.get("ssl_timeout", 5),
                follow_redirects=True,
            )
        return self._httpx_client

    async def _async_check_https(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Async HTTPS check using httpx (for future async support).
        
        This method provides async capabilities for checking HTTPS
        without blocking the event loop.
        
        Args:
            url: Target URL to check
            
        Returns:
            Dict with connection info or None
        """
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=self._config.get("ssl_timeout", 5),
            ) as client:
                response = await client.get(url)
                
                # Extract connection info if available
                return {
                    "status_code": response.status_code,
                    "is_ssl": url.startswith("https"),
                    "headers": dict(response.headers),
                    "url": str(response.url),
                }
        except httpx.TimeoutException:
            return {"error": "timeout", "message": "Request timed out"}
        except httpx.ConnectError as e:
            return {"error": "connect_error", "message": str(e)}
        except Exception as e:
            return {"error": "unknown", "message": str(e)}

    def configure(self, **kwargs) -> None:
        """
        Configure cryptographic failures attack parameters.
        
        NOTE: This module always runs in FULL AGGRESSIVE mode.
        All checks are always enabled for maximum security coverage.
        """
        super().configure(**kwargs)
        # Always run full aggressive scan - no options
        self._config["check_ssl"] = True
        self._config["check_headers"] = True
        self._config["check_sensitive_data"] = True
        self._config["check_certificate_chain"] = True
        self._config["check_common_ssl_endpoints"] = True
        self._config["ssl_timeout"] = kwargs.get("ssl_timeout", 8)  # Longer timeout for aggressive

    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options - simplified for aggressive mode."""
        options = super().get_config_options()
        # Only expose basic options - all security checks always enabled
        options.update(
            {
                "ssl_timeout": {
                    "type": "integer",
                    "default": 8,
                    "description": "SSL connection timeout in seconds (aggressive mode)",
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
        Get SSL/TLS information from a host with detailed certificate and cipher analysis.

        Args:
            hostname: Target hostname
            port: Target port (default: 443)

        Returns:
            Dictionary with comprehensive SSL info or None if connection failed
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self._config.get("ssl_timeout", 5)
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in both binary and parsed forms
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Parse certificate details safely
                    cert_info = {}
                    if cert:
                        # Extract issuer
                        issuer_parts = []
                        for item in cert.get("issuer", []):
                            for key, value in item:
                                issuer_parts.append(f"{key}={value}")
                        cert_info["issuer"] = ", ".join(issuer_parts) if issuer_parts else "Unknown"

                        # Extract subject
                        subject_parts = []
                        for item in cert.get("subject", []):
                            for key, value in item:
                                subject_parts.append(f"{key}={value}")
                        cert_info["subject"] = ", ".join(subject_parts) if subject_parts else "Unknown"

                        # Parse expiration date safely
                        if "notAfter" in cert:
                            try:
                                # Parse the certificate expiration date
                                expiry_str = cert["notAfter"]
                                # Try multiple date formats
                                for fmt in ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"]:
                                    try:
                                        expiry_date = datetime.strptime(expiry_str, fmt)
                                        cert_info["expiry_date"] = expiry_date.isoformat()
                                        cert_info["days_until_expiry"] = (expiry_date - datetime.now()).days
                                        cert_info["is_expired"] = expiry_date < datetime.now()
                                        break
                                    except ValueError:
                                        continue
                            except Exception as e:
                                cert_info["expiry_date"] = cert.get("notAfter", "Unknown")
                                cert_info["expiry_parse_error"] = str(e)

                        # Parse start date
                        if "notBefore" in cert:
                            try:
                                start_str = cert["notBefore"]
                                for fmt in ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"]:
                                    try:
                                        start_date = datetime.strptime(start_str, fmt)
                                        cert_info["start_date"] = start_date.isoformat()
                                        break
                                    except ValueError:
                                        continue
                            except Exception:
                                cert_info["start_date"] = cert.get("notBefore", "Unknown")

                        # Check if self-signed
                        cert_info["is_self_signed"] = cert_info.get("issuer") == cert_info.get("subject")

                        # Extract serial number
                        cert_info["serial_number"] = cert.get("serialNumber", "Unknown")

                        # Extract version
                        cert_info["version"] = cert.get("version", "Unknown")

                    return {
                        "certificate": cert,
                        "certificate_info": cert_info,
                        "cipher": cipher,
                        "version": version,
                        "cipher_name": cipher[0] if cipher else None,
                        "cipher_protocol": cipher[1] if cipher and len(cipher) > 1 else None,
                        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                    }
        except socket.timeout:
            return {"error": "timeout", "message": "SSL connection timed out"}
        except ssl.SSLError as e:
            return {"error": "ssl_error", "message": str(e)}
        except socket.error as e:
            return {"error": "socket_error", "message": str(e)}
        except Exception as e:
            return {"error": "unknown", "message": str(e)}


    def _check_deprecated_protocols(self, hostname: str, port: int = 443) -> List[Tuple[str, bool, Optional[str]]]:
        """
        Check which deprecated protocols are supported with detailed error reporting.

        Returns:
            List of (protocol_name, is_supported, error_message) tuples
        """
        results = []

        for proto_name, proto_version in self.DEPRECATED_PROTOCOLS.items():
            if proto_version is None:
                # Protocol not available in this Python/OpenSSL version
                continue

            try:
                context = ssl.SSLContext(proto_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection(
                    (hostname, port), timeout=self._config.get("ssl_timeout", 5)
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        results.append((proto_name, True, None))
            except ssl.SSLError as e:
                # SSL error means protocol was rejected (good)
                results.append((proto_name, False, f"SSL Error: {str(e)}"))
            except socket.timeout:
                results.append((proto_name, False, "Connection timeout"))
            except socket.error as e:
                results.append((proto_name, False, f"Socket error: {str(e)}"))
            except Exception as e:
                results.append((proto_name, False, f"Error: {str(e)}"))

        return results

    def _test_ssl_configuration(self, target: str) -> Generator[Finding, None, None]:
        """Test SSL/TLS configuration with comprehensive checks - AGGRESSIVE mode."""
        # Robust URL parsing
        parsed = urlparse(self._normalize_url(target))
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not hostname:
            yield Finding(
                title="Invalid Target URL",
                severity=Severity.MEDIUM,
                description="Could not parse hostname from target URL",
                evidence=f"Target: {target}",
                remediation="Provide a valid URL with a hostname",
                metadata={"target": target},
            )
            return

        # Check if HTTPS is available
        ssl_info = self._get_ssl_info(hostname, 443 if port == 80 else port)

        # Handle errors from SSL connection
        if ssl_info and "error" in ssl_info:
            error_type = ssl_info.get("error")
            error_msg = ssl_info.get("message", "Unknown error")
            
            if error_type == "timeout":
                severity = Severity.MEDIUM
                description = "SSL/TLS connection timed out"
            elif error_type == "ssl_error":
                severity = Severity.HIGH
                description = f"SSL/TLS error occurred: {error_msg}"
            else:
                severity = Severity.MEDIUM
                description = f"Could not establish SSL/TLS connection: {error_msg}"

            yield Finding(
                title="SSL/TLS Connection Failed",
                severity=severity,
                description=description,
                evidence=f"Host: {hostname}:{port}, Error: {error_type} - {error_msg}",
                remediation="Ensure the server has valid SSL/TLS configuration and is accessible",
                metadata={"hostname": hostname, "port": port, "error": error_type},
            )
            ssl_info = None

        if ssl_info is None and parsed.scheme == "http":
            # Target uses HTTP, check if HTTPS is available at all
            ssl_info_443 = self._get_ssl_info(hostname, 443)

            if ssl_info_443 is None or "error" in ssl_info_443:
                yield Finding(
                    title="No HTTPS Available",
                    severity=Severity.HIGH,
                    description="The target does not appear to support HTTPS. "
                    "All data is transmitted in plain text.",
                    evidence=f"Host: {hostname}, Port 443 not responding to SSL/TLS",
                    remediation="Enable HTTPS with a valid SSL/TLS certificate. "
                    "Use TLS 1.2 or higher with strong cipher suites. "
                    "Consider using Let's Encrypt for free certificates.",
                    metadata={"hostname": hostname, "scheme": parsed.scheme},
                )
            else:
                yield Finding(
                    title="HTTP Used Instead of HTTPS",
                    severity=Severity.MEDIUM,
                    description="The target is using HTTP but HTTPS is available. "
                    "Traffic should be redirected to HTTPS.",
                    evidence=f"HTTP: {target}, HTTPS available on port 443",
                    remediation="Redirect all HTTP traffic to HTTPS (HTTP 301/308). "
                    "Implement HSTS to prevent downgrade attacks. "
                    "Update all internal links to use HTTPS.",
                    metadata={"hostname": hostname, "http_url": target},
                )
                ssl_info = ssl_info_443

        if ssl_info and "error" not in ssl_info:
            cert_info = ssl_info.get("certificate_info", {})
            
            # Check for self-signed certificate
            if cert_info.get("is_self_signed"):
                yield Finding(
                    title="Self-Signed Certificate Detected",
                    severity=Severity.HIGH,
                    description="The server is using a self-signed certificate which browsers will not trust",
                    evidence=f"Issuer: {cert_info.get('issuer', 'Unknown')}\n"
                            f"Subject: {cert_info.get('subject', 'Unknown')}",
                    remediation="Obtain a certificate from a trusted Certificate Authority. "
                    "Let's Encrypt provides free, automated certificates.",
                    metadata={"issuer": cert_info.get("issuer"), "subject": cert_info.get("subject")},
                )

            # Check certificate expiration
            if cert_info.get("is_expired"):
                yield Finding(
                    title="Expired SSL Certificate",
                    severity=Severity.HIGH,
                    description="The SSL/TLS certificate has expired",
                    evidence=f"Expiry Date: {cert_info.get('expiry_date', 'Unknown')}\n"
                            f"Days Past Expiry: {abs(cert_info.get('days_until_expiry', 0))}",
                    remediation="Renew the SSL/TLS certificate immediately",
                    metadata={"expiry_date": cert_info.get("expiry_date")},
                )
            elif cert_info.get("days_until_expiry", 365) < 30:
                yield Finding(
                    title="SSL Certificate Expiring Soon",
                    severity=Severity.MEDIUM,
                    description=f"SSL certificate expires in {cert_info.get('days_until_expiry')} days",
                    evidence=f"Expiry Date: {cert_info.get('expiry_date', 'Unknown')}",
                    remediation="Renew the SSL certificate before expiration",
                    metadata={"days_until_expiry": cert_info.get("days_until_expiry")},
                )

            # Check cipher strength
            cipher_name = ssl_info.get("cipher_name", "")
            cipher_bits = ssl_info.get("cipher_bits", 0)
            cipher_protocol = ssl_info.get("cipher_protocol", "")

            # Check for weak ciphers
            weak_ciphers_found = []
            for weak_cipher in self.WEAK_CIPHERS:
                if weak_cipher.upper() in cipher_name.upper():
                    weak_ciphers_found.append(weak_cipher)

            if weak_ciphers_found:
                yield Finding(
                    title="Weak Cipher Suite in Use",
                    severity=Severity.HIGH,
                    description=f"The server is using weak cipher suite: {cipher_name}",
                    evidence=f"Cipher: {cipher_name}\n"
                            f"Protocol: {cipher_protocol}\n"
                            f"Key Bits: {cipher_bits}\n"
                            f"Weak Elements: {', '.join(weak_ciphers_found)}\n"
                            f"Certificate Issuer: {cert_info.get('issuer', 'Unknown')}",
                    remediation="Configure the server to use only strong cipher suites. "
                    "Recommended: ECDHE+AESGCM, ECDHE+CHACHA20. "
                    "Disable: RC4, DES, 3DES, MD5, NULL, EXPORT, CBC mode, and anonymous ciphers. "
                    "Use Mozilla SSL Configuration Generator for best practices.",
                    metadata={
                        "cipher": cipher_name,
                        "bits": cipher_bits,
                        "protocol": cipher_protocol,
                        "weak_ciphers": weak_ciphers_found,
                    },
                )

            # Check cipher bit strength
            if cipher_bits and cipher_bits < 128:
                yield Finding(
                    title="Weak Cipher Key Length",
                    severity=Severity.MEDIUM,
                    description=f"The cipher key length is too short: {cipher_bits} bits",
                    evidence=f"Cipher: {cipher_name}\n"
                            f"Key Bits: {cipher_bits}\n"
                            f"Protocol: {cipher_protocol}",
                    remediation="Use ciphers with at least 128-bit key length. "
                    "256-bit AES-GCM is recommended for maximum security.",
                    metadata={"cipher": cipher_name, "bits": cipher_bits},
                )

            # Check TLS version
            version = ssl_info.get("version", "")
            if version in self.INSECURE_PROTOCOL_NAMES:
                yield Finding(
                    title="Deprecated TLS/SSL Version in Use",
                    severity=Severity.HIGH,
                    description=f"Server is currently using deprecated protocol: {version}",
                    evidence=f"Protocol: {version}\n"
                            f"Description: {self.INSECURE_PROTOCOL_NAMES[version]}\n"
                            f"Cipher: {cipher_name}",
                    remediation="Disable TLS 1.0, TLS 1.1, and all SSL versions. "
                    "Use TLS 1.2 or TLS 1.3 only. "
                    "TLS 1.3 is preferred for best security and performance.",
                    metadata={"version": version, "cipher": cipher_name},
                )

        # Check for deprecated protocol support
        deprecated = self._check_deprecated_protocols(hostname, 443 if port == 80 else port)

        supported_deprecated = []
        for proto_name, is_supported, error_msg in deprecated:
            if is_supported:
                supported_deprecated.append(proto_name)

        if supported_deprecated:
            yield Finding(
                title="Deprecated Protocols Supported",
                severity=Severity.MEDIUM,
                description=f"The server supports {len(supported_deprecated)} deprecated protocol(s)",
                evidence=f"Supported Deprecated Protocols:\n" + 
                        "\n".join([f"  • {proto}: {self.INSECURE_PROTOCOL_NAMES.get(proto, 'Deprecated')}" 
                                  for proto in supported_deprecated]),
                remediation="Disable support for TLS 1.0, TLS 1.1, SSLv2, and SSLv3. "
                "Only allow TLS 1.2 and TLS 1.3. "
                "Update server configuration (nginx, apache, IIS) to remove old protocols. "
                "This is required for PCI-DSS compliance.",
                metadata={
                    "deprecated_protocols": supported_deprecated,
                    "hostname": hostname,
                    "port": port,
                },
            )

        self.set_progress(33)

    def _test_security_headers(self, target: str) -> Generator[Finding, None, None]:
        """Test for missing security headers - AGGRESSIVE mode."""
        base_url = self._normalize_url(target)
        response = self._make_request(base_url)

        if not response:
            return

        headers = self._get_headers_dict(response)
        missing_headers = []

        # Check all security headers aggressively
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                missing_headers.append(header_info["name"])
                yield Finding(
                    title=f"Missing {header_info['name']}",
                    severity=header_info["severity"],
                    description=header_info["description"],
                    evidence=f"URL: {base_url}, Missing Header: {header_name}",
                    remediation=f"Add the {header_name} header to all HTTPS responses",
                    metadata={"url": base_url, "header": header_name},
                )

        # Check for HSTS specific issues
        if "strict-transport-security" in headers:
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
            
            # Check if includeSubDomains is missing
            if "includesubdomains" not in hsts_value.lower():
                yield Finding(
                    title="HSTS Missing includeSubDomains",
                    severity=Severity.LOW,
                    description="HSTS header does not include includeSubDomains directive",
                    evidence=f"Header: {hsts_value}",
                    remediation="Add includeSubDomains to HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    metadata={"hsts_value": hsts_value},
                )

        # Check for secure cookie attributes on Set-Cookie headers
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            cookie_issues = []
            if "secure" not in set_cookie.lower():
                cookie_issues.append("Secure flag missing")
            if "httponly" not in set_cookie.lower():
                cookie_issues.append("HttpOnly flag missing")
            if "samesite" not in set_cookie.lower():
                cookie_issues.append("SameSite attribute missing")
            
            if cookie_issues:
                yield Finding(
                    title="Insecure Cookie Configuration",
                    severity=Severity.MEDIUM,
                    description=f"Cookie has security issues: {', '.join(cookie_issues)}",
                    evidence=f"Set-Cookie: {set_cookie[:100]}...\nIssues: {', '.join(cookie_issues)}",
                    remediation="Add Secure, HttpOnly, and SameSite=Strict flags to all cookies",
                    metadata={"cookie_header": set_cookie, "issues": cookie_issues},
                )

        self.set_progress(66)

    def _test_sensitive_data_exposure(self, target: str) -> Generator[Finding, None, None]:
        """Scan for sensitive data exposure in responses - SUPER AGGRESSIVE mode."""
        base_url = self._normalize_url(target)

        # SUPER AGGRESSIVE: 100+ endpoints to test
        endpoints = [
            # Root and common
            "", "/", "/index", "/home", "/main",
            
            # API endpoints - all versions
            "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
            "/api/config", "/api/v1/config", "/api/v2/config",
            "/api/settings", "/api/v1/settings",
            "/api/users", "/api/v1/users", "/api/user",
            "/api/admin", "/api/v1/admin",
            "/api/debug", "/api/v1/debug",
            "/api/status", "/api/health", "/api/version",
            "/api/info", "/api/environment", "/api/env",
            
            # Configuration files
            "/config", "/configuration", "/settings", "/options",
            "/config.json", "/config.xml", "/config.yaml", "/config.yml",
            "/settings.json", "/settings.xml",
            "/application.properties", "/application.yml",
            
            # Environment and secrets
            "/.env", "/.env.local", "/.env.development", "/.env.production",
            "/.env.test", "/.env.staging", "/.environment",
            "/env", "/environment", "/.envrc",
            
            # Debug and development
            "/debug", "/debug/", "/debug/config", "/debug/settings",
            "/info", "/status", "/health", "/healthcheck",
            "/metrics", "/monitoring", "/stats", "/statistics",
            "/profiler", "/trace", "/logs",
            
            # Documentation and API specs
            "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
            "/api-docs", "/api/docs", "/api/documentation",
            "/docs", "/documentation", "/openapi.json",
            "/redoc", "/graphql", "/graphiql",
            
            # Admin interfaces
            "/admin", "/admin/", "/admin/config", "/admin/settings",
            "/admin/debug", "/admin/env", "/admin/status",
            "/administrator", "/manage", "/management",
            "/console", "/dashboard", "/control-panel",
            
            # Source control and build files
            "/.git/config", "/.git/HEAD", "/.gitignore",
            "/.svn/entries", "/.hg/hgrc",
            "/package.json", "/package-lock.json", "/composer.json",
            "/Gemfile", "/Gemfile.lock", "/requirements.txt",
            "/pom.xml", "/build.gradle", "/gradle.properties",
            "/yarn.lock", "/npm-debug.log",
            
            # Server configuration
            "/web.config", "/Web.config", "/.htaccess", "/.htpasswd",
            "/httpd.conf", "/nginx.conf", "/apache.conf",
            "/robots.txt", "/sitemap.xml", "/.well-known/",
            
            # Database and backup files
            "/database.sql", "/backup.sql", "/dump.sql",
            "/db.sql", "/database.sqlite", "/app.db",
            "/backup", "/backups", "/dumps",
            
            # Authentication and keys
            "/keys", "/certs", "/certificates",
            "/.ssh/id_rsa", "/.ssh/id_dsa",
            "/privatekey.pem", "/private.key",
            "/oauth", "/oauth/token", "/token",
            "/login", "/auth", "/authenticate",
            
            # Cloud and container configs
            "/docker-compose.yml", "/Dockerfile",
            "/kubernetes.yml", "/k8s.yaml",
            "/.dockerignore", "/terraform.tfstate",
            "/ansible.cfg", "/playbook.yml",
            
            # Framework specific
            "/wp-config.php", "/wp-admin/",  # WordPress
            "/app/config/parameters.yml",  # Symfony
            "/.rails/credentials.yml.enc",  # Rails
            "/settings.py", "/local_settings.py",  # Django
            "/appsettings.json", "/appsettings.Development.json",  # .NET
            
            # Test and dev files
            "/test", "/tests", "/testing",
            "/dev", "/development", "/staging",
            "/phpinfo.php", "/info.php", "/test.php",
            "/phpmyadmin/", "/adminer.php",
        ]

        found_issues = {}  # Track issues by type to consolidate

        for endpoint in endpoints:
            if self.is_cancelled():
                break

            url = self._build_url(base_url, endpoint) if endpoint else base_url
            response = self._make_request(url)

            if not response or response.status_code not in [200, 201, 202]:
                continue

            content = response.text

            for pattern, description in self.SENSITIVE_DATA_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)

                if matches:
                    if description not in found_issues:
                        found_issues[description] = []
                    
                    # Limit the number of matches shown per type
                    for match in matches[:5]:  # Max 5 per pattern
                        # Redact sensitive data in evidence
                        if len(match) > 10:
                            redacted = match[:5] + "..." + match[-3:]
                        else:
                            redacted = "***REDACTED***"
                        
                        found_issues[description].append({
                            "url": url,
                            "match": redacted,
                            "endpoint": endpoint
                        })

            time.sleep(self._delay_between_requests * 0.3)  # Faster for super aggressive

        # Consolidate findings by type
        for description, occurrences in found_issues.items():
            urls_affected = list(set([occ["url"] for occ in occurrences]))
            total_matches = len(occurrences)
            
            # Sample evidence
            sample_evidence = occurrences[:5]
            evidence_text = f"Found {total_matches} occurrence(s) across {len(urls_affected)} endpoint(s)\n\n"
            evidence_text += "Sample locations:\n"
            for ev in sample_evidence:
                evidence_text += f"  • {ev['endpoint'] or '/'}: {ev['match']}\n"

            yield Finding(
                title=f"Sensitive Data Exposure: {description}",
                severity=Severity.HIGH,
                description=f"Potentially sensitive data found in responses: {description}",
                evidence=evidence_text,
                remediation="Remove sensitive data from responses. "
                "Use proper access controls and encryption for sensitive data. "
                "Never expose credentials, keys, or tokens in API responses. "
                "Implement proper authentication and authorization.",
                metadata={
                    "pattern_type": description,
                    "match_count": total_matches,
                    "affected_urls": urls_affected[:10],  # Limit to 10 URLs
                },
            )

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
