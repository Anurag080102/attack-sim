"""
A08:2021 - Software and Data Integrity Failures Attack Module.

This module implements detection of integrity failure vulnerabilities including:
- Insecure deserialization
- Unsigned/unverified software updates
- CI/CD pipeline vulnerabilities
- Missing integrity checks
- Untrusted data sources
"""

import re
import time
import base64
import json
from typing import Generator, Dict, Any, List
from urllib.parse import urljoin

from attacks.base import Finding, Severity
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase
from attacks.owasp import OWASPRegistry


@OWASPRegistry.register("a08")
class IntegrityFailuresAttack(BaseOWASPAttack):
    """
    Software and Data Integrity Failures scanner.
    
    Tests for insecure deserialization and integrity verification issues.
    """
    
    name = "Integrity Failures Scanner"
    description = "Detects integrity failures including insecure deserialization"
    category = OWASPCategory.A08_INTEGRITY_FAILURES
    
    # Serialization indicators in responses/cookies
    SERIALIZATION_PATTERNS = {
        "java": [
            r'rO0AB',  # Base64 Java serialized object
            r'aced0005',  # Java serialization magic bytes (hex)
            r'org\.apache\.',
            r'java\.util\.',
            r'java\.lang\.',
        ],
        "php": [
            r'a:\d+:\{',  # PHP serialized array
            r'O:\d+:"',   # PHP serialized object
            r's:\d+:"',   # PHP serialized string
            r'i:\d+;',    # PHP serialized integer
        ],
        "python": [
            r'\x80\x03',  # Python pickle
            r'\x80\x04',  # Python pickle protocol 4
            r'ccopy_reg',
            r'c__builtin__',
        ],
        "dotnet": [
            r'AAEAAAD',  # .NET BinaryFormatter
            r'TypeName.*Assembly',
            r'System\.',
        ],
        "node": [
            r'_$$ND_FUNC$$_',  # node-serialize
        ]
    }
    
    # Common cookie/parameter names that might contain serialized data
    SERIALIZED_PARAM_NAMES = [
        "data", "object", "session", "state", "viewstate",
        "__VIEWSTATE", "__EVENTVALIDATION", "token", "auth",
        "user", "profile", "cart", "basket", "order",
        "preferences", "settings", "config"
    ]
    
    # Subresource Integrity check
    SRI_PATTERN = r'<script[^>]+integrity=["\']sha\d+-'
    
    # CDN resources that should have SRI
    CDN_PATTERNS = [
        r'cdn\.jsdelivr\.net',
        r'cdnjs\.cloudflare\.com',
        r'unpkg\.com',
        r'ajax\.googleapis\.com',
        r'code\.jquery\.com',
        r'stackpath\.bootstrapcdn\.com',
        r'maxcdn\.bootstrapcdn\.com',
    ]
    
    def __init__(self):
        super().__init__()
    
    def configure(self, **kwargs) -> None:
        """
        Configure integrity failures attack parameters.
        
        Args:
            test_serialization: Test for insecure serialization (default: True)
            test_sri: Test for missing Subresource Integrity (default: True)
            test_jwt: Test for JWT vulnerabilities (default: True)
        """
        super().configure(**kwargs)
        self._config["test_serialization"] = kwargs.get("test_serialization", True)
        self._config["test_sri"] = kwargs.get("test_sri", True)
        self._config["test_jwt"] = kwargs.get("test_jwt", True)
    
    def get_config_options(self) -> Dict[str, Any]:
        """Get configuration options."""
        options = super().get_config_options()
        options.update({
            "test_serialization": {
                "type": "boolean",
                "default": True,
                "description": "Test for insecure serialization"
            },
            "test_sri": {
                "type": "boolean",
                "default": True,
                "description": "Test for missing Subresource Integrity"
            },
            "test_jwt": {
                "type": "boolean",
                "default": True,
                "description": "Test for JWT vulnerabilities"
            }
        })
        return options
    
    def get_test_cases(self) -> List[OWASPTestCase]:
        """Get test cases for integrity failures."""
        return [
            OWASPTestCase(
                name="Insecure Deserialization",
                description="Detect serialized objects in cookies and parameters",
                category=OWASPCategory.A08_INTEGRITY_FAILURES,
                payloads=[],
                detection_patterns=list(self.SERIALIZATION_PATTERNS.keys())
            ),
            OWASPTestCase(
                name="Missing Subresource Integrity",
                description="Check for missing SRI on CDN resources",
                category=OWASPCategory.A08_INTEGRITY_FAILURES,
                payloads=[],
                detection_patterns=self.CDN_PATTERNS
            ),
            OWASPTestCase(
                name="JWT Vulnerabilities",
                description="Test for JWT algorithm confusion and weak signing",
                category=OWASPCategory.A08_INTEGRITY_FAILURES,
                payloads=[],
                detection_patterns=["jwt", "bearer", "token"]
            )
        ]
    
    def _detect_serialization_format(self, data: str) -> List[Dict[str, str]]:
        """Detect serialization format from data."""
        findings = []
        
        for lang, patterns in self.SERIALIZATION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    findings.append({
                        "language": lang,
                        "pattern": pattern
                    })
        
        return findings
    
    def _test_serialization_in_cookies(self, target: str) -> Generator[Finding, None, None]:
        """Test for serialized objects in cookies."""
        if not self._config.get("test_serialization", True):
            return
        
        base_url = self._normalize_url(target)
        response = self._make_request(base_url)
        
        if not response:
            return
        
        # Check cookies for serialized data
        for cookie in response.cookies:
            cookie_value = cookie.value or ""
            
            # Try to decode base64
            try:
                decoded: str = base64.b64decode(cookie_value).decode('utf-8', errors='ignore')
            except Exception:
                decoded = cookie_value
            
            serialization_found = self._detect_serialization_format(cookie_value)
            serialization_found.extend(self._detect_serialization_format(decoded))
            
            if serialization_found:
                for finding in serialization_found:
                    value_preview = cookie_value[:100] if len(cookie_value) > 100 else cookie_value
                    yield Finding(
                        title=f"Potential Serialized Object in Cookie ({finding['language']})",
                        severity=Severity.HIGH,
                        description=f"Cookie '{cookie.name}' appears to contain a serialized "
                                   f"{finding['language']} object. This may be vulnerable to "
                                   "insecure deserialization attacks.",
                        evidence=f"Cookie: {cookie.name}, Pattern: {finding['pattern']}, "
                                f"Value preview: {value_preview}...",
                        remediation="Avoid deserializing untrusted data. Use safer data formats "
                                   "like JSON. Implement integrity checks (HMAC) on serialized data. "
                                   "Consider using language-specific secure alternatives.",
                        metadata={
                            "cookie_name": cookie.name,
                            "language": finding['language'],
                            "pattern": finding['pattern']
                        }
                    )
        
        # Check response body for serialized data indicators
        content = response.text
        
        for lang, patterns in self.SERIALIZATION_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                if matches:
                    yield Finding(
                        title=f"Serialized Data Detected ({lang})",
                        severity=Severity.MEDIUM,
                        description=f"Response contains patterns indicating {lang} serialization",
                        evidence=f"Pattern: {pattern}, Matches: {len(matches)}",
                        remediation="Review the use of serialization. Ensure proper integrity "
                                   "verification and avoid deserializing untrusted input.",
                        metadata={
                            "language": lang,
                            "pattern": pattern,
                            "match_count": len(matches)
                        }
                    )
        
        self.set_progress(33)
    
    def _test_subresource_integrity(self, target: str) -> Generator[Finding, None, None]:
        """Test for missing Subresource Integrity on CDN resources."""
        if not self._config.get("test_sri", True):
            return
        
        base_url = self._normalize_url(target)
        response = self._make_request(base_url)
        
        if not response:
            return
        
        content = response.text
        
        # Find all script and link tags
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        link_pattern = r'<link[^>]+href=["\']([^"\']+\.(?:css|js))["\'][^>]*>'
        
        scripts = re.findall(script_pattern, content, re.IGNORECASE)
        links = re.findall(link_pattern, content, re.IGNORECASE)
        
        all_resources = scripts + links
        
        cdn_resources_without_sri = []
        
        for resource in all_resources:
            # Check if resource is from a CDN
            is_cdn = any(re.search(cdn, resource, re.IGNORECASE) for cdn in self.CDN_PATTERNS)
            
            if is_cdn:
                # Check if the tag has integrity attribute
                # We need to find the full tag for this resource
                resource_escaped = re.escape(resource)
                tag_pattern = rf'<(?:script|link)[^>]*{resource_escaped}[^>]*>'
                tag_match = re.search(tag_pattern, content, re.IGNORECASE)
                
                if tag_match:
                    tag = tag_match.group(0)
                    has_integrity = 'integrity=' in tag.lower()
                    
                    if not has_integrity:
                        cdn_resources_without_sri.append(resource)
        
        if cdn_resources_without_sri:
            yield Finding(
                title="Missing Subresource Integrity (SRI)",
                severity=Severity.MEDIUM,
                description=f"Found {len(cdn_resources_without_sri)} CDN resources without "
                           "Subresource Integrity hashes. This could allow attackers to inject "
                           "malicious code if the CDN is compromised.",
                evidence=f"Resources without SRI: {cdn_resources_without_sri[:5]}",
                remediation="Add integrity attributes to all external script and stylesheet tags. "
                           "Use tools like srihash.org to generate hashes. "
                           "Example: integrity=\"sha384-...\" crossorigin=\"anonymous\"",
                metadata={
                    "resources": cdn_resources_without_sri,
                    "count": len(cdn_resources_without_sri)
                }
            )
        
        self.set_progress(66)
    
    def _test_jwt_vulnerabilities(self, target: str) -> Generator[Finding, None, None]:
        """Test for JWT vulnerabilities."""
        if not self._config.get("test_jwt", True):
            return
        
        base_url = self._normalize_url(target)
        response = self._make_request(base_url)
        
        if not response:
            return
        
        # Look for JWTs in cookies and headers
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        
        # Check cookies
        for cookie in response.cookies:
            cookie_value = cookie.value or ""
            jwt_match = re.search(jwt_pattern, cookie_value)
            if jwt_match:
                jwt = jwt_match.group(0)
                yield from self._analyze_jwt(jwt, f"cookie:{cookie.name}")
        
        # Check response headers
        for header, value in response.headers.items():
            jwt_match = re.search(jwt_pattern, value)
            if jwt_match:
                jwt = jwt_match.group(0)
                yield from self._analyze_jwt(jwt, f"header:{header}")
        
        # Check response body
        jwt_matches = re.findall(jwt_pattern, response.text)
        for jwt in jwt_matches[:3]:  # Limit to first 3
            yield from self._analyze_jwt(jwt, "response_body")
        
        self.set_progress(100)
    
    def _analyze_jwt(self, jwt: str, source: str) -> Generator[Finding, None, None]:
        """Analyze a JWT for vulnerabilities."""
        try:
            parts = jwt.split('.')
            if len(parts) != 3:
                return
            
            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
            header = json.loads(header_json)
            
            # Decode payload
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            # Check algorithm
            alg = header.get('alg', '').upper()
            
            if alg == 'NONE':
                yield Finding(
                    title="JWT Uses 'none' Algorithm",
                    severity=Severity.CRITICAL,
                    description="JWT is configured to use 'none' algorithm, meaning no signature "
                               "verification. Attackers can forge tokens.",
                    evidence=f"Source: {source}, Algorithm: {alg}",
                    remediation="Always use strong signing algorithms (RS256, ES256). "
                               "Never accept 'none' algorithm in production.",
                    metadata={"source": source, "algorithm": alg}
                )
            
            if alg in ['HS256', 'HS384', 'HS512']:
                yield Finding(
                    title="JWT Uses Symmetric Algorithm",
                    severity=Severity.LOW,
                    description=f"JWT uses symmetric algorithm ({alg}). If the secret is weak "
                               "or leaked, tokens can be forged.",
                    evidence=f"Source: {source}, Algorithm: {alg}",
                    remediation="Consider using asymmetric algorithms (RS256, ES256) for "
                               "better security. Ensure HMAC secrets are strong (256+ bits).",
                    metadata={"source": source, "algorithm": alg}
                )
            
            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'private', 'key', 'credit', 'ssn']
            for key in payload.keys():
                if any(s in key.lower() for s in sensitive_keys):
                    yield Finding(
                        title="JWT Contains Potentially Sensitive Data",
                        severity=Severity.MEDIUM,
                        description=f"JWT payload contains field '{key}' which may be sensitive",
                        evidence=f"Source: {source}, Sensitive field: {key}",
                        remediation="Avoid storing sensitive data in JWTs. JWTs are encoded, "
                                   "not encrypted, and can be easily decoded.",
                        metadata={"source": source, "field": key}
                    )
            
            # Check expiration
            if 'exp' not in payload:
                yield Finding(
                    title="JWT Missing Expiration",
                    severity=Severity.MEDIUM,
                    description="JWT does not have an expiration time (exp claim)",
                    evidence=f"Source: {source}",
                    remediation="Always include an 'exp' claim in JWTs to limit token lifetime.",
                    metadata={"source": source}
                )
            
        except Exception:
            # Invalid JWT format, skip
            pass
    
    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute integrity failures attack against the target.
        
        Args:
            target: Target URL
            
        Yields:
            Finding objects for each vulnerability discovered
        """
        self.reset()
        self._is_running = True
        
        yield Finding(
            title="Integrity Failures Scan Started",
            severity=Severity.INFO,
            description="Starting scan for software and data integrity failures",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target}
        )
        
        try:
            # Test 1: Serialization in Cookies (0-33%)
            yield from self._test_serialization_in_cookies(target)
            
            # Test 2: Subresource Integrity (33-66%)
            yield from self._test_subresource_integrity(target)
            
            # Test 3: JWT Vulnerabilities (66-100%)
            yield from self._test_jwt_vulnerabilities(target)
            
        finally:
            self._is_running = False
            self.set_progress(100.0)
            self.cleanup()
        
        yield Finding(
            title="Integrity Failures Scan Completed",
            severity=Severity.INFO,
            description="Completed scan for software and data integrity failures",
            evidence=f"Target: {target}",
            remediation="N/A - Informational",
            metadata={"target": target}
        )
