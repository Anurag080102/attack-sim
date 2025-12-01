"""
Brute Force Attack Module.

This module implements a brute force attack against web authentication endpoints.
It systematically tries username/password combinations to discover valid credentials.
"""

import time
import itertools
import string
from typing import Generator, Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException

from attacks.base import BaseAttack, Finding, Severity
from attacks import AttackRegistry


@AttackRegistry.register("bruteforce")
class BruteForceAttack(BaseAttack):
    """
    Brute force attack for web authentication.
    
    This attack systematically generates and tries password combinations
    against a target login endpoint.
    """
    
    name = "Brute Force Attack"
    description = "Systematically tries password combinations to discover valid credentials"
    
    # Default configuration
    DEFAULT_CHARSET = string.ascii_lowercase + string.digits
    DEFAULT_MIN_LENGTH = 1
    DEFAULT_MAX_LENGTH = 4
    DEFAULT_MAX_THREADS = 5
    DEFAULT_TIMEOUT = 10
    DEFAULT_DELAY = 0.1
    
    def __init__(self):
        super().__init__()
        self._total_attempts = 0
        self._current_attempt = 0
        self._session: Optional[requests.Session] = None
    
    def configure(self, **kwargs) -> None:
        """
        Configure brute force attack parameters.
        
        Args:
            username: Target username to attack (required)
            charset: Character set for password generation (default: lowercase + digits)
            min_length: Minimum password length (default: 1)
            max_length: Maximum password length (default: 4)
            login_url: Full URL of the login endpoint (optional, will use target + /login)
            username_field: Name of username form field (default: username)
            password_field: Name of password form field (default: password)
            success_indicator: String that indicates successful login (default: None)
            failure_indicator: String that indicates failed login (default: "invalid")
            max_threads: Maximum concurrent threads (default: 5)
            timeout: Request timeout in seconds (default: 10)
            delay: Delay between requests in seconds (default: 0.1)
            http_method: HTTP method to use (default: POST)
        """
        self._config = {
            "username": kwargs.get("username", "admin"),
            "charset": kwargs.get("charset", self.DEFAULT_CHARSET),
            "min_length": kwargs.get("min_length", self.DEFAULT_MIN_LENGTH),
            "max_length": kwargs.get("max_length", self.DEFAULT_MAX_LENGTH),
            "login_url": kwargs.get("login_url"),
            "username_field": kwargs.get("username_field", "username"),
            "password_field": kwargs.get("password_field", "password"),
            "success_indicator": kwargs.get("success_indicator"),
            "failure_indicator": kwargs.get("failure_indicator", "invalid"),
            "max_threads": kwargs.get("max_threads", self.DEFAULT_MAX_THREADS),
            "timeout": kwargs.get("timeout", self.DEFAULT_TIMEOUT),
            "delay": kwargs.get("delay", self.DEFAULT_DELAY),
            "http_method": kwargs.get("http_method", "POST").upper(),
        }
    
    def get_config_options(self) -> Dict[str, Any]:
        """Return available configuration options."""
        return {
            "username": {
                "type": "string",
                "default": "admin",
                "description": "Target username to attack",
                "required": True
            },
            "charset": {
                "type": "string",
                "default": self.DEFAULT_CHARSET,
                "description": "Characters to use for password generation"
            },
            "min_length": {
                "type": "integer",
                "default": self.DEFAULT_MIN_LENGTH,
                "description": "Minimum password length",
                "min": 1,
                "max": 8
            },
            "max_length": {
                "type": "integer",
                "default": self.DEFAULT_MAX_LENGTH,
                "description": "Maximum password length",
                "min": 1,
                "max": 8
            },
            "login_url": {
                "type": "string",
                "default": None,
                "description": "Full login URL (defaults to target/login)"
            },
            "username_field": {
                "type": "string",
                "default": "username",
                "description": "Form field name for username"
            },
            "password_field": {
                "type": "string",
                "default": "password",
                "description": "Form field name for password"
            },
            "success_indicator": {
                "type": "string",
                "default": None,
                "description": "Text indicating successful login"
            },
            "failure_indicator": {
                "type": "string",
                "default": "invalid",
                "description": "Text indicating failed login"
            },
            "max_threads": {
                "type": "integer",
                "default": self.DEFAULT_MAX_THREADS,
                "description": "Maximum concurrent threads",
                "min": 1,
                "max": 20
            },
            "timeout": {
                "type": "integer",
                "default": self.DEFAULT_TIMEOUT,
                "description": "Request timeout in seconds"
            },
            "delay": {
                "type": "float",
                "default": self.DEFAULT_DELAY,
                "description": "Delay between requests in seconds"
            },
            "http_method": {
                "type": "select",
                "default": "POST",
                "options": ["POST", "GET"],
                "description": "HTTP method to use"
            }
        }
    
    def _generate_passwords(self) -> Generator[str, None, None]:
        """Generate passwords based on charset and length configuration."""
        charset = self._config.get("charset", self.DEFAULT_CHARSET)
        min_len = self._config.get("min_length", self.DEFAULT_MIN_LENGTH)
        max_len = self._config.get("max_length", self.DEFAULT_MAX_LENGTH)
        
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)
    
    def _count_total_passwords(self) -> int:
        """Calculate total number of passwords to try."""
        charset = self._config.get("charset", self.DEFAULT_CHARSET)
        min_len = self._config.get("min_length", self.DEFAULT_MIN_LENGTH)
        max_len = self._config.get("max_length", self.DEFAULT_MAX_LENGTH)
        
        total = 0
        charset_len = len(charset)
        for length in range(min_len, max_len + 1):
            total += charset_len ** length
        return total
    
    def _try_login(self, target: str, password: str) -> Dict[str, Any]:
        """
        Attempt login with given password.
        
        Returns:
            dict with keys: success (bool), password (str), response_code (int), error (str or None)
        """
        if self._session is None:
            self._session = requests.Session()
        
        login_url = self._config.get("login_url") or f"{target.rstrip('/')}/login"
        username = self._config["username"]
        username_field = self._config["username_field"]
        password_field = self._config["password_field"]
        timeout = self._config.get("timeout", self.DEFAULT_TIMEOUT)
        http_method = self._config.get("http_method", "POST")
        
        data = {
            username_field: username,
            password_field: password
        }
        
        try:
            if http_method == "POST":
                response = self._session.post(login_url, data=data, timeout=timeout, allow_redirects=True)
            else:
                response = self._session.get(login_url, params=data, timeout=timeout, allow_redirects=True)
            
            # Check for success/failure indicators
            success_indicator = self._config.get("success_indicator")
            failure_indicator = self._config.get("failure_indicator", "invalid")
            
            is_success = False
            
            if success_indicator:
                # If success indicator is defined, look for it
                is_success = success_indicator.lower() in response.text.lower()
            elif failure_indicator:
                # If no success indicator, check absence of failure indicator
                is_success = failure_indicator.lower() not in response.text.lower()
            else:
                # Fall back to checking status codes
                is_success = response.status_code in [200, 302] and "logout" in response.text.lower()
            
            return {
                "success": is_success,
                "password": password,
                "response_code": response.status_code,
                "error": None
            }
            
        except RequestException as e:
            return {
                "success": False,
                "password": password,
                "response_code": None,
                "error": str(e)
            }
    
    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute brute force attack against the target.
        
        Args:
            target: Target URL (base URL of the application)
            
        Yields:
            Finding objects for discovered credentials or notable events
        """
        self.reset()
        self._is_running = True
        self._session = requests.Session()
        
        # Calculate total attempts
        self._total_attempts = self._count_total_passwords()
        self._current_attempt = 0
        
        username = self._config.get("username", "admin")
        max_threads = self._config.get("max_threads", self.DEFAULT_MAX_THREADS)
        delay = self._config.get("delay", self.DEFAULT_DELAY)
        
        # Yield info finding about attack start
        yield Finding(
            title="Brute Force Attack Started",
            severity=Severity.INFO,
            description=f"Starting brute force attack against user '{username}'",
            evidence=f"Target: {target}, Total passwords to try: {self._total_attempts}",
            remediation="N/A - Informational",
            metadata={
                "username": username,
                "total_attempts": self._total_attempts,
                "charset_length": len(self._config.get("charset", self.DEFAULT_CHARSET)),
                "min_length": self._config.get("min_length"),
                "max_length": self._config.get("max_length")
            }
        )
        
        found_credentials = False
        errors_count = 0
        
        try:
            if max_threads > 1:
                # Multi-threaded execution
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    futures = {}
                    password_gen = self._generate_passwords()
                    
                    # Submit initial batch
                    for password in itertools.islice(password_gen, max_threads * 2):
                        if self._is_cancelled:
                            break
                        future = executor.submit(self._try_login, target, password)
                        futures[future] = password
                    
                    while futures and not self._is_cancelled:
                        # Process completed futures
                        done_futures = []
                        for future in as_completed(futures, timeout=0.1):
                            done_futures.append(future)
                        
                        for future in done_futures:
                            if self._is_cancelled:
                                break
                                
                            result = future.result()
                            self._current_attempt += 1
                            self.set_progress((self._current_attempt / self._total_attempts) * 100)
                            
                            if result["error"]:
                                errors_count += 1
                            
                            if result["success"]:
                                found_credentials = True
                                yield Finding(
                                    title="Valid Credentials Found",
                                    severity=Severity.CRITICAL,
                                    description=f"Successfully discovered valid password for user '{username}'",
                                    evidence=f"Username: {username}, Password: {result['password']}",
                                    remediation="Implement account lockout policy, use strong passwords, enable MFA",
                                    metadata={
                                        "username": username,
                                        "password": result["password"],
                                        "attempts": self._current_attempt
                                    }
                                )
                                self.cancel()
                                break
                            
                            # Remove processed future and submit new one
                            del futures[future]
                            try:
                                next_password = next(password_gen)
                                new_future = executor.submit(self._try_login, target, next_password)
                                futures[new_future] = next_password
                            except StopIteration:
                                pass
                        
                        if delay > 0:
                            time.sleep(delay)
            else:
                # Single-threaded execution
                for password in self._generate_passwords():
                    if self._is_cancelled:
                        break
                    
                    result = self._try_login(target, password)
                    self._current_attempt += 1
                    self.set_progress((self._current_attempt / self._total_attempts) * 100)
                    
                    if result["error"]:
                        errors_count += 1
                    
                    if result["success"]:
                        found_credentials = True
                        yield Finding(
                            title="Valid Credentials Found",
                            severity=Severity.CRITICAL,
                            description=f"Successfully discovered valid password for user '{username}'",
                            evidence=f"Username: {username}, Password: {result['password']}",
                            remediation="Implement account lockout policy, use strong passwords, enable MFA",
                            metadata={
                                "username": username,
                                "password": result["password"],
                                "attempts": self._current_attempt
                            }
                        )
                        break
                    
                    if delay > 0:
                        time.sleep(delay)
        
        finally:
            self._is_running = False
            self.set_progress(100.0)
            
            if self._session:
                self._session.close()
                self._session = None
        
        # Yield summary finding
        if not found_credentials:
            yield Finding(
                title="Brute Force Attack Completed",
                severity=Severity.INFO,
                description=f"No valid credentials found for user '{username}'",
                evidence=f"Attempted {self._current_attempt} password combinations",
                remediation="N/A - No vulnerabilities found",
                metadata={
                    "username": username,
                    "attempts": self._current_attempt,
                    "errors": errors_count,
                    "cancelled": self._is_cancelled
                }
            )
        
        if errors_count > 0:
            yield Finding(
                title="Connection Errors During Attack",
                severity=Severity.LOW,
                description=f"Encountered {errors_count} connection errors during the attack",
                evidence=f"Error rate: {(errors_count/self._current_attempt)*100:.1f}%",
                remediation="Check target availability and network connectivity",
                metadata={"error_count": errors_count}
            )
