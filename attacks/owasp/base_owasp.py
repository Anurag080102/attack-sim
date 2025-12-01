"""
Base OWASP attack module providing common functionality for OWASP Top 10 scanners.
"""

from abc import abstractmethod
from typing import Generator, Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import requests
from urllib.parse import urljoin, urlparse

from attacks.base import BaseAttack, Finding, Severity


class OWASPCategory(Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_MONITORING = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"


@dataclass
class OWASPTestCase:
    """Represents a single OWASP test case."""
    name: str
    description: str
    category: OWASPCategory
    payloads: List[str]
    detection_patterns: List[str]


class BaseOWASPAttack(BaseAttack):
    """
    Abstract base class for OWASP Top 10 attack modules.
    
    Provides common functionality for OWASP vulnerability scanning including:
    - HTTP request utilities
    - Common detection patterns
    - Standard test case execution
    """
    
    category: OWASPCategory = None
    
    def __init__(self):
        super().__init__()
        self._session: Optional[requests.Session] = None
        self._timeout: int = 10
        self._user_agent: str = "AttackSim Security Scanner/1.0"
        self._verify_ssl: bool = True
        self._follow_redirects: bool = True
        self._max_retries: int = 3
        self._delay_between_requests: float = 0.1
    
    def configure(self, **kwargs) -> None:
        """
        Configure OWASP attack parameters.
        
        Args:
            timeout: Request timeout in seconds (default: 10)
            user_agent: Custom User-Agent string
            verify_ssl: Whether to verify SSL certificates (default: True)
            follow_redirects: Whether to follow redirects (default: True)
            max_retries: Maximum request retries (default: 3)
            delay: Delay between requests in seconds (default: 0.1)
        """
        self._timeout = kwargs.get("timeout", self._timeout)
        self._user_agent = kwargs.get("user_agent", self._user_agent)
        self._verify_ssl = kwargs.get("verify_ssl", self._verify_ssl)
        self._follow_redirects = kwargs.get("follow_redirects", self._follow_redirects)
        self._max_retries = kwargs.get("max_retries", self._max_retries)
        self._delay_between_requests = kwargs.get("delay", self._delay_between_requests)
        self._config.update(kwargs)
    
    def get_config_options(self) -> Dict[str, Any]:
        """Get available configuration options for OWASP attacks."""
        return {
            "timeout": {
                "type": "integer",
                "default": 10,
                "description": "Request timeout in seconds"
            },
            "user_agent": {
                "type": "string",
                "default": "AttackSim Security Scanner/1.0",
                "description": "Custom User-Agent header"
            },
            "verify_ssl": {
                "type": "boolean",
                "default": True,
                "description": "Verify SSL certificates"
            },
            "follow_redirects": {
                "type": "boolean",
                "default": True,
                "description": "Follow HTTP redirects"
            },
            "max_retries": {
                "type": "integer",
                "default": 3,
                "description": "Maximum request retries"
            },
            "delay": {
                "type": "float",
                "default": 0.1,
                "description": "Delay between requests in seconds"
            }
        }
    
    def _get_session(self) -> requests.Session:
        """
        Get or create an HTTP session.
        
        Returns:
            requests.Session: Configured session object
        """
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                "User-Agent": self._user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            })
        return self._session
    
    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None
    ) -> Optional[requests.Response]:
        """
        Make an HTTP request with error handling.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            data: Form data for POST requests
            headers: Additional headers
            params: URL parameters
            json_data: JSON data for POST requests
            
        Returns:
            Response object if successful, None otherwise
        """
        session = self._get_session()
        
        try:
            response = session.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                params=params,
                json=json_data,
                timeout=self._timeout,
                verify=self._verify_ssl,
                allow_redirects=self._follow_redirects
            )
            return response
        except requests.RequestException:
            return None
    
    def _normalize_url(self, target: str) -> str:
        """
        Normalize target URL to ensure it has a scheme.
        
        Args:
            target: Target URL or IP
            
        Returns:
            Normalized URL with scheme
        """
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        return target.rstrip("/")
    
    def _build_url(self, base: str, path: str) -> str:
        """
        Build a full URL from base and path.
        
        Args:
            base: Base URL
            path: Path to append
            
        Returns:
            Full URL
        """
        return urljoin(base + "/", path.lstrip("/"))
    
    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """
        Extract form information from HTML.
        
        Args:
            html: HTML content
            
        Returns:
            List of form dictionaries with action, method, and inputs
        """
        # Simple form extraction - could be enhanced with BeautifulSoup
        import re
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        action_pattern = r'action=["\']([^"\']*)["\']'
        method_pattern = r'method=["\']([^"\']*)["\']'
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            action_match = re.search(action_pattern, form_html, re.IGNORECASE)
            method_match = re.search(method_pattern, form_html, re.IGNORECASE)
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            forms.append({
                "action": action_match.group(1) if action_match else "",
                "method": method_match.group(1).upper() if method_match else "GET",
                "inputs": inputs
            })
        
        return forms
    
    def _check_response_for_patterns(
        self,
        response: requests.Response,
        patterns: List[str],
        case_sensitive: bool = False
    ) -> List[str]:
        """
        Check response content for patterns.
        
        Args:
            response: HTTP response object
            patterns: List of patterns to search for
            case_sensitive: Whether search is case sensitive
            
        Returns:
            List of matched patterns
        """
        import re
        content = response.text
        matches = []
        
        flags = 0 if case_sensitive else re.IGNORECASE
        
        for pattern in patterns:
            if re.search(pattern, content, flags):
                matches.append(pattern)
        
        return matches
    
    def _get_headers_dict(self, response: requests.Response) -> Dict[str, str]:
        """
        Get response headers as a dictionary.
        
        Args:
            response: HTTP response object
            
        Returns:
            Dictionary of headers (lowercase keys)
        """
        return {k.lower(): v for k, v in response.headers.items()}
    
    @abstractmethod
    def get_test_cases(self) -> List[OWASPTestCase]:
        """
        Get the test cases for this OWASP category.
        
        Returns:
            List of OWASPTestCase objects to execute
        """
        pass
    
    @abstractmethod
    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute the OWASP attack and yield findings.
        
        Args:
            target: Target URL
            
        Yields:
            Finding objects for each vulnerability discovered
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get attack module information including OWASP category."""
        info = super().get_info()
        if self.category:
            info["owasp_category"] = self.category.value
        return info
    
    def cleanup(self) -> None:
        """Clean up resources after attack completion."""
        if self._session:
            self._session.close()
            self._session = None
