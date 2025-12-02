"""
Attack Module Unit Tests

This module contains unit tests for all attack modules including:
- Base attack functionality
- Brute force attack
- Dictionary attack
- OWASP attack modules
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import os

from attacks.base import BaseAttack, Finding, Severity
from attacks import AttackRegistry
from attacks.bruteforce import BruteForceAttack
from attacks.dictionary import DictionaryAttack
from attacks.owasp import OWASPRegistry
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory

# Import OWASP attack modules to ensure they're registered
import attacks.owasp.a01_broken_access
import attacks.owasp.a02_crypto_failures
import attacks.owasp.a03_injection
import attacks.owasp.a04_insecure_design
import attacks.owasp.a05_security_misconfig
import attacks.owasp.a06_outdated_components
import attacks.owasp.a07_auth_failures
import attacks.owasp.a08_integrity_failures
import attacks.owasp.a09_logging_monitoring
import attacks.owasp.a10_ssrf


class TestSeverityEnum:
    """Test cases for the Severity enum."""

    def test_severity_values(self):
        """Test that severity enum has correct values."""
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_severity_count(self):
        """Test that all severity levels are present."""
        assert len(Severity) == 5


class TestFinding:
    """Test cases for the Finding dataclass."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="A test finding",
            evidence="Some evidence",
            remediation="Fix the issue"
        )

        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.description == "A test finding"
        assert finding.evidence == "Some evidence"
        assert finding.remediation == "Fix the issue"

    def test_finding_to_dict(self):
        """Test finding serialization to dictionary."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.CRITICAL,
            description="Critical issue",
            evidence="Evidence here",
            remediation="Fix immediately"
        )

        result = finding.to_dict()

        assert result["title"] == "Test Finding"
        assert result["severity"] == "critical"
        assert result["description"] == "Critical issue"
        assert result["evidence"] == "Evidence here"
        assert result["remediation"] == "Fix immediately"
        assert "timestamp" in result
        assert "metadata" in result

    def test_finding_with_metadata(self):
        """Test finding with custom metadata."""
        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Test",
            evidence="Test",
            remediation="Test",
            metadata={"key": "value", "count": 42}
        )

        assert finding.metadata["key"] == "value"
        assert finding.metadata["count"] == 42


class TestAttackRegistry:
    """Test cases for the attack registry."""

    def test_get_registered_attack(self):
        """Test getting a registered attack class."""
        attack_class = AttackRegistry.get("bruteforce")
        assert attack_class == BruteForceAttack

    def test_get_nonexistent_attack(self):
        """Test getting a non-existent attack returns None."""
        attack_class = AttackRegistry.get("nonexistent_attack")
        assert attack_class is None

    def test_create_attack_instance(self):
        """Test creating an attack instance."""
        attack = AttackRegistry.create("bruteforce")
        assert attack is not None
        assert isinstance(attack, BruteForceAttack)

    def test_create_attack_with_config(self):
        """Test creating an attack with configuration."""
        attack = AttackRegistry.create("bruteforce", username="testuser", max_threads=2)
        assert attack is not None
        assert attack._config["username"] == "testuser"
        assert attack._config["max_threads"] == 2

    def test_list_attacks(self):
        """Test listing all registered attacks."""
        attacks = AttackRegistry.list_attacks()
        assert len(attacks) >= 2  # At least bruteforce and dictionary

        attack_ids = [a["id"] for a in attacks]
        assert "bruteforce" in attack_ids
        assert "dictionary" in attack_ids

    def test_get_attack_ids(self):
        """Test getting list of attack IDs."""
        ids = AttackRegistry.get_attack_ids()
        assert "bruteforce" in ids
        assert "dictionary" in ids


class TestBruteForceAttack:
    """Test cases for the BruteForce attack module."""

    def test_attack_name_and_description(self):
        """Test attack has correct name and description."""
        attack = BruteForceAttack()
        assert attack.name == "Brute Force Attack"
        assert "password" in attack.description.lower() or "brute" in attack.description.lower()

    def test_default_configuration(self):
        """Test default configuration is applied."""
        attack = BruteForceAttack()
        attack.configure()

        assert attack._config["username"] == "admin"
        assert attack._config["min_length"] == 1
        assert attack._config["max_length"] == 4
        assert attack._config["max_threads"] == 5

    def test_custom_configuration(self):
        """Test custom configuration is applied correctly."""
        attack = BruteForceAttack()
        attack.configure(
            username="testuser",
            charset="abc",
            min_length=2,
            max_length=3,
            max_threads=2
        )

        assert attack._config["username"] == "testuser"
        assert attack._config["charset"] == "abc"
        assert attack._config["min_length"] == 2
        assert attack._config["max_length"] == 3
        assert attack._config["max_threads"] == 2

    def test_password_generation(self):
        """Test password generation based on configuration."""
        attack = BruteForceAttack()
        attack.configure(charset="ab", min_length=1, max_length=2)

        passwords = list(attack._generate_passwords())

        # Should have a, b, aa, ab, ba, bb = 6 passwords
        expected = ["a", "b", "aa", "ab", "ba", "bb"]
        assert passwords == expected

    def test_count_total_passwords(self):
        """Test total password count calculation."""
        attack = BruteForceAttack()
        attack.configure(charset="abc", min_length=1, max_length=2)

        # 3^1 + 3^2 = 3 + 9 = 12
        count = attack._count_total_passwords()
        assert count == 12

    def test_get_config_options(self):
        """Test config options are properly defined."""
        attack = BruteForceAttack()
        options = attack.get_config_options()

        assert "username" in options
        assert "charset" in options
        assert "min_length" in options
        assert "max_length" in options
        assert "max_threads" in options
        assert "timeout" in options

    def test_progress_tracking(self):
        """Test progress tracking functionality."""
        attack = BruteForceAttack()

        assert attack.get_progress() == 0.0

        attack.set_progress(50.0)
        assert attack.get_progress() == 50.0

        # Test bounds
        attack.set_progress(150.0)
        assert attack.get_progress() == 100.0

        attack.set_progress(-10.0)
        assert attack.get_progress() == 0.0

    def test_cancellation(self):
        """Test attack cancellation."""
        attack = BruteForceAttack()

        assert not attack.is_cancelled()

        attack.cancel()
        assert attack.is_cancelled()

    def test_reset(self):
        """Test attack state reset."""
        attack = BruteForceAttack()
        attack.set_progress(50.0)
        attack.cancel()

        attack.reset()

        assert attack.get_progress() == 0.0
        assert not attack.is_cancelled()
        assert not attack.is_running()

    @patch('attacks.bruteforce.requests.Session')
    def test_run_generates_findings(self, mock_session_class):
        """Test that running attack generates findings."""
        # Setup mock
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "invalid credentials"
        mock_session.post.return_value = mock_response
        mock_session.request.return_value = mock_response

        attack = BruteForceAttack()
        attack.configure(
            username="admin",
            charset="a",
            min_length=1,
            max_length=1,
            max_threads=1,
            timeout=1,
            delay=0
        )

        findings = list(attack.run("http://localhost"))

        # Should have at least start and end informational findings
        assert len(findings) >= 2
        assert any("Started" in f.title for f in findings)


class TestDictionaryAttack:
    """Test cases for the Dictionary attack module."""

    def test_attack_name_and_description(self):
        """Test attack has correct name and description."""
        attack = DictionaryAttack()
        assert attack.name == "Dictionary Attack"
        assert "wordlist" in attack.description.lower() or "dictionary" in attack.description.lower()

    def test_default_configuration(self):
        """Test default configuration is applied."""
        attack = DictionaryAttack()
        attack.configure()

        assert attack._config["username"] == "admin"
        assert "common_passwords.txt" in attack._config["password_wordlist"]
        assert attack._config["max_threads"] == 5

    def test_custom_configuration(self):
        """Test custom configuration is applied correctly."""
        attack = DictionaryAttack()
        attack.configure(
            username="testuser",
            password_wordlist="custom/passwords.txt",
            max_threads=2,
            stop_on_success=False
        )

        assert attack._config["username"] == "testuser"
        assert attack._config["password_wordlist"] == "custom/passwords.txt"
        assert attack._config["max_threads"] == 2
        assert attack._config["stop_on_success"] is False

    def test_wordlist_loading(self):
        """Test loading passwords from wordlist file."""
        attack = DictionaryAttack()
        attack.configure()

        # Load the actual common passwords wordlist
        passwords = attack._load_wordlist("wordlists/common_passwords.txt")

        assert len(passwords) > 0
        assert "password" in passwords or "123456" in passwords

    def test_wordlist_file_not_found(self):
        """Test handling of missing wordlist file."""
        attack = DictionaryAttack()

        with pytest.raises(FileNotFoundError):
            attack._load_wordlist("nonexistent/wordlist.txt")

    def test_get_config_options(self):
        """Test config options are properly defined."""
        attack = DictionaryAttack()
        options = attack.get_config_options()

        assert "username" in options
        assert "password_wordlist" in options
        assert "username_wordlist" in options
        assert "max_threads" in options
        assert "stop_on_success" in options

    def test_credential_generation_single_user(self):
        """Test credential generation with single username."""
        # Create a temporary wordlist
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("pass1\npass2\npass3\n")
            temp_wordlist = f.name

        try:
            attack = DictionaryAttack()
            attack._base_path = Path(temp_wordlist).parent.parent
            attack.configure(
                username="admin",
                password_wordlist=temp_wordlist
            )

            credentials = list(attack._generate_credentials())

            assert len(credentials) == 3
            assert all(cred[0] == "admin" for cred in credentials)
            assert [cred[1] for cred in credentials] == ["pass1", "pass2", "pass3"]
        finally:
            os.unlink(temp_wordlist)

    def test_count_total_attempts(self):
        """Test counting total credential combinations."""
        # Create temporary wordlists
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("pass1\npass2\npass3\n")
            temp_passwords = f.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("user1\nuser2\n")
            temp_users = f.name

        try:
            attack = DictionaryAttack()
            attack.configure(
                password_wordlist=temp_passwords,
                username_wordlist=temp_users
            )

            # Should be 2 users * 3 passwords = 6
            count = attack._count_total_attempts()
            assert count == 6
        finally:
            os.unlink(temp_passwords)
            os.unlink(temp_users)


class TestOWASPRegistry:
    """Test cases for the OWASP attack registry."""

    def test_get_registered_owasp_attack(self):
        """Test getting a registered OWASP attack class."""
        attack_class = OWASPRegistry.get("a03")
        assert attack_class is not None

    def test_get_nonexistent_owasp_attack(self):
        """Test getting a non-existent OWASP attack returns None."""
        attack_class = OWASPRegistry.get("nonexistent")
        assert attack_class is None

    def test_create_owasp_attack_instance(self):
        """Test creating an OWASP attack instance."""
        attack = OWASPRegistry.create("a03")
        assert attack is not None
        assert isinstance(attack, BaseOWASPAttack)

    def test_list_owasp_attacks(self):
        """Test listing all registered OWASP attacks."""
        attacks = OWASPRegistry.list_attacks()
        assert len(attacks) >= 10  # Should have all 10 OWASP categories

        attack_ids = [a["id"] for a in attacks]
        assert "a01" in attack_ids
        assert "a03" in attack_ids
        assert "a10" in attack_ids

    def test_get_attack_ids(self):
        """Test getting list of OWASP attack IDs."""
        ids = OWASPRegistry.get_attack_ids()
        expected_ids = ["a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"]
        for expected_id in expected_ids:
            assert expected_id in ids

    def test_get_all_categories(self):
        """Test getting all OWASP categories."""
        categories = OWASPRegistry.get_all_categories()
        assert len(categories) == 10  # OWASP Top 10

        category_names = [c["id"] for c in categories]
        assert "A01_BROKEN_ACCESS_CONTROL" in category_names
        assert "A03_INJECTION" in category_names


class TestOWASPCategory:
    """Test cases for OWASP category enum."""

    def test_all_categories_present(self):
        """Test that all OWASP Top 10 categories are defined."""
        assert len(OWASPCategory) == 10

        expected = [
            "A01_BROKEN_ACCESS_CONTROL",
            "A02_CRYPTOGRAPHIC_FAILURES",
            "A03_INJECTION",
            "A04_INSECURE_DESIGN",
            "A05_SECURITY_MISCONFIGURATION",
            "A06_VULNERABLE_COMPONENTS",
            "A07_AUTH_FAILURES",
            "A08_INTEGRITY_FAILURES",
            "A09_LOGGING_MONITORING",
            "A10_SSRF"
        ]

        for name in expected:
            assert hasattr(OWASPCategory, name)

    def test_category_values(self):
        """Test that category values include proper descriptions."""
        assert "Broken Access Control" in OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value
        assert "Injection" in OWASPCategory.A03_INJECTION.value
        assert "Server-Side Request Forgery" in OWASPCategory.A10_SSRF.value


class TestBaseOWASPAttack:
    """Test cases for the base OWASP attack class."""

    def test_normalize_url_without_scheme(self):
        """Test URL normalization adds http scheme."""
        attack = OWASPRegistry.create("a03")

        url = attack._normalize_url("example.com")
        assert url == "http://example.com"

    def test_normalize_url_with_http(self):
        """Test URL normalization preserves http scheme."""
        attack = OWASPRegistry.create("a03")

        url = attack._normalize_url("http://example.com")
        assert url == "http://example.com"

    def test_normalize_url_with_https(self):
        """Test URL normalization preserves https scheme."""
        attack = OWASPRegistry.create("a03")

        url = attack._normalize_url("https://example.com")
        assert url == "https://example.com"

    def test_normalize_url_removes_trailing_slash(self):
        """Test URL normalization removes trailing slash."""
        attack = OWASPRegistry.create("a03")

        url = attack._normalize_url("http://example.com/")
        assert url == "http://example.com"

    def test_build_url(self):
        """Test URL building from base and path."""
        attack = OWASPRegistry.create("a03")

        url = attack._build_url("http://example.com", "/api/test")
        assert url == "http://example.com/api/test"

    def test_owasp_config_options(self):
        """Test OWASP-specific config options."""
        attack = OWASPRegistry.create("a03")
        options = attack.get_config_options()

        assert "timeout" in options
        assert "user_agent" in options
        assert "verify_ssl" in options
        assert "follow_redirects" in options

    def test_get_info_includes_category(self):
        """Test that get_info includes OWASP category."""
        attack = OWASPRegistry.create("a03")
        info = attack.get_info()

        assert "owasp_category" in info
        assert "Injection" in info["owasp_category"]


class TestInjectionAttack:
    """Test cases specific to the Injection attack module."""

    def test_injection_payloads_exist(self):
        """Test that injection payloads are defined."""
        from attacks.owasp.a03_injection import InjectionAttack

        assert len(InjectionAttack.SQL_PAYLOADS) > 0
        assert len(InjectionAttack.XSS_PAYLOADS) > 0
        assert len(InjectionAttack.CMD_PAYLOADS) > 0

    def test_sql_error_patterns_exist(self):
        """Test that SQL error patterns are defined."""
        from attacks.owasp.a03_injection import InjectionAttack

        assert len(InjectionAttack.SQL_ERROR_PATTERNS) > 0

    def test_get_test_cases(self):
        """Test getting test cases for injection."""
        attack = OWASPRegistry.create("a03")
        test_cases = attack.get_test_cases()

        assert len(test_cases) >= 3  # SQL, XSS, Command injection

        names = [tc.name for tc in test_cases]
        assert any("SQL" in name for name in names)
        assert any("XSS" in name for name in names)
        assert any("Command" in name for name in names)

    def test_configure_injection_options(self):
        """Test configuring injection-specific options."""
        attack = OWASPRegistry.create("a03")
        attack.configure(
            test_sql=True,
            test_xss=False,
            test_cmd=True
        )

        assert attack._config["test_sql"] is True
        assert attack._config["test_xss"] is False
        assert attack._config["test_cmd"] is True


class TestAttackIntegration:
    """Integration tests for attack modules."""

    def test_all_attacks_can_be_instantiated(self):
        """Test that all registered attacks can be instantiated."""
        # Core attacks
        for attack_info in AttackRegistry.list_attacks():
            attack = AttackRegistry.create(attack_info["id"])
            assert attack is not None
            assert attack.name is not None
            assert attack.description is not None

        # OWASP attacks
        for attack_info in OWASPRegistry.list_attacks():
            attack = OWASPRegistry.create(attack_info["id"])
            assert attack is not None
            assert attack.name is not None
            assert attack.description is not None

    def test_all_attacks_have_config_options(self):
        """Test that all attacks have configuration options defined."""
        # Core attacks
        for attack_info in AttackRegistry.list_attacks():
            attack = AttackRegistry.create(attack_info["id"])
            options = attack.get_config_options()
            assert isinstance(options, dict)

        # OWASP attacks
        for attack_info in OWASPRegistry.list_attacks():
            attack = OWASPRegistry.create(attack_info["id"])
            options = attack.get_config_options()
            assert isinstance(options, dict)

    def test_all_attacks_support_progress_tracking(self):
        """Test that all attacks support progress tracking."""
        all_attacks = []

        for attack_info in AttackRegistry.list_attacks():
            all_attacks.append(AttackRegistry.create(attack_info["id"]))

        for attack_info in OWASPRegistry.list_attacks():
            all_attacks.append(OWASPRegistry.create(attack_info["id"]))

        for attack in all_attacks:
            assert hasattr(attack, "get_progress")
            assert hasattr(attack, "set_progress")
            assert attack.get_progress() == 0.0

    def test_all_attacks_support_cancellation(self):
        """Test that all attacks support cancellation."""
        all_attacks = []

        for attack_info in AttackRegistry.list_attacks():
            all_attacks.append(AttackRegistry.create(attack_info["id"]))

        for attack_info in OWASPRegistry.list_attacks():
            all_attacks.append(OWASPRegistry.create(attack_info["id"]))

        for attack in all_attacks:
            assert hasattr(attack, "cancel")
            assert hasattr(attack, "is_cancelled")
            assert not attack.is_cancelled()
            attack.cancel()
            assert attack.is_cancelled()
