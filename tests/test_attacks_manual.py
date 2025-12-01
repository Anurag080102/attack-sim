"""
Manual test script for brute force and dictionary attacks.

This script tests the attack modules to ensure they function correctly.
Run with: python -m tests.test_attacks_manual
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from attacks.bruteforce import BruteForceAttack  # noqa: E402
from attacks.dictionary import DictionaryAttack  # noqa: E402
from attacks import AttackRegistry  # noqa: E402


def test_bruteforce_registration():
    """Test that BruteForceAttack is registered correctly."""
    print("=" * 60)
    print("Testing BruteForce Attack Registration")
    print("=" * 60)

    # Check registry
    attack_class = AttackRegistry.get("bruteforce")
    assert attack_class is not None, "BruteForceAttack not registered"
    assert attack_class == BruteForceAttack, "Wrong class registered"

    # Create instance
    attack = AttackRegistry.create("bruteforce")
    assert attack is not None, "Failed to create attack instance"
    assert attack.name == "Brute Force Attack", f"Wrong name: {attack.name}"

    print(f"✓ Attack registered: {attack.name}")
    print(f"✓ Description: {attack.description}")
    print(f"✓ Config options: {list(attack.get_config_options().keys())}")
    print()


def test_dictionary_registration():
    """Test that DictionaryAttack is registered correctly."""
    print("=" * 60)
    print("Testing Dictionary Attack Registration")
    print("=" * 60)

    # Check registry
    attack_class = AttackRegistry.get("dictionary")
    assert attack_class is not None, "DictionaryAttack not registered"
    assert attack_class == DictionaryAttack, "Wrong class registered"

    # Create instance
    attack = AttackRegistry.create("dictionary")
    assert attack is not None, "Failed to create attack instance"
    assert attack.name == "Dictionary Attack", f"Wrong name: {attack.name}"

    print(f"✓ Attack registered: {attack.name}")
    print(f"✓ Description: {attack.description}")
    print(f"✓ Config options: {list(attack.get_config_options().keys())}")
    print()


def test_bruteforce_password_generation():
    """Test password generation in brute force attack."""
    print("=" * 60)
    print("Testing BruteForce Password Generation")
    print("=" * 60)

    attack = BruteForceAttack()
    attack.configure(
        username="admin",
        charset="abc",
        min_length=1,
        max_length=2,
    )

    # Generate passwords
    passwords = list(attack._generate_passwords())

    # Expected: a, b, c, aa, ab, ac, ba, bb, bc, ca, cb, cc = 12 passwords
    expected_count = 3 + 9  # 3^1 + 3^2
    assert (
        len(passwords) == expected_count
    ), f"Expected {expected_count} passwords, got {len(passwords)}"

    print(f"✓ Generated {len(passwords)} passwords")
    print(f"✓ Sample passwords: {passwords[:5]}...")
    total_count = attack._count_total_passwords()
    print(f"✓ Total count calculation: {total_count}")
    print()


def test_dictionary_wordlist_loading():
    """Test wordlist loading in dictionary attack."""
    print("=" * 60)
    print("Testing Dictionary Wordlist Loading")
    print("=" * 60)

    attack = DictionaryAttack()
    attack.configure(
        username="admin", password_wordlist="wordlists/common_passwords.txt"
    )

    # Load wordlist
    try:
        passwords = attack._load_wordlist("wordlists/common_passwords.txt")
        print(f"✓ Loaded {len(passwords)} passwords from wordlist")
        print(f"✓ Sample passwords: {passwords[:5]}...")
    except FileNotFoundError as e:
        print(f"✗ Failed to load wordlist: {e}")
        return False

    # Load usernames
    try:
        usernames = attack._load_wordlist("wordlists/common_usernames.txt")
        print(f"✓ Loaded {len(usernames)} usernames from wordlist")
        print(f"✓ Sample usernames: {usernames[:5]}...")
    except FileNotFoundError as e:
        print(f"✗ Failed to load wordlist: {e}")
        return False

    print()
    return True


def test_attack_list():
    """Test listing all registered attacks."""
    print("=" * 60)
    print("Testing Attack Registry List")
    print("=" * 60)

    attacks = AttackRegistry.list_attacks()

    print(f"✓ Registered attacks: {len(attacks)}")
    for attack in attacks:
        print(f"  - {attack['id']}: {attack['name']}")

    assert len(attacks) >= 2, "Expected at least 2 registered attacks"
    print()


def test_bruteforce_dry_run():
    """Test brute force attack dry run (without actual target)."""
    print("=" * 60)
    print("Testing BruteForce Attack Dry Run")
    print("=" * 60)

    attack = BruteForceAttack()
    attack.configure(
        username="test",
        charset="ab",
        min_length=1,
        max_length=2,
        max_threads=1,
        timeout=2,
    )

    # Run against non-existent target (will generate error findings)
    target = "http://localhost:99999"
    findings = []

    print(f"Running attack against {target} (expected to fail)")

    try:
        for finding in attack.run(target):
            findings.append(finding)
            print(f"  Finding: [{finding.severity.value}] {finding.title}")

            # Limit the run
            if attack._current_attempt > 3:
                attack.cancel()
                break
    except Exception as e:
        print(f"  Expected error: {e}")

    print(f"✓ Attack generated {len(findings)} findings")
    print(f"✓ Attack progress: {attack.get_progress():.1f}%")
    print(f"✓ Attack cancelled: {attack.is_cancelled()}")
    print()


def test_dictionary_dry_run():
    """Test dictionary attack dry run (without actual target)."""
    print("=" * 60)
    print("Testing Dictionary Attack Dry Run")
    print("=" * 60)

    attack = DictionaryAttack()
    attack.configure(
        username="admin",
        password_wordlist="wordlists/common_passwords.txt",
        max_threads=1,
        timeout=2,
    )

    # Run against non-existent target (will generate error findings)
    target = "http://localhost:99999"
    findings = []

    print(f"Running attack against {target} (expected to fail)")

    try:
        for finding in attack.run(target):
            findings.append(finding)
            print(f"  Finding: [{finding.severity.value}] {finding.title}")

            # Limit the run
            if attack._current_attempt > 3:
                attack.cancel()
                break
    except Exception as e:
        print(f"  Expected error: {e}")

    print(f"✓ Attack generated {len(findings)} findings")
    print(f"✓ Attack progress: {attack.get_progress():.1f}%")
    print()


def main():
    """Run all manual tests."""
    print()
    print("=" * 60)
    print("ATTACK-SIM MANUAL TEST SUITE")
    print("=" * 60)
    print()

    try:
        test_bruteforce_registration()
        test_dictionary_registration()
        test_bruteforce_password_generation()
        test_dictionary_wordlist_loading()
        test_attack_list()
        test_bruteforce_dry_run()
        test_dictionary_dry_run()

        print("=" * 60)
        print("ALL TESTS PASSED ✓")
        print("=" * 60)
        return 0

    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
