"""
OWASP attack module registry.

This module provides a specialized registry for OWASP Top 10 attack modules,
with categorization and filtering capabilities.
"""

from typing import Dict, Type, Optional, List
from attacks.owasp.base_owasp import BaseOWASPAttack, OWASPCategory, OWASPTestCase


class OWASPRegistry:
    """
    Registry for managing OWASP attack modules.

    Provides methods to register, discover, and instantiate OWASP attack modules
    with category-based filtering.
    """

    _attacks: Dict[str, Type[BaseOWASPAttack]] = {}

    @classmethod
    def register(cls, attack_id: str):
        """
        Decorator to register an OWASP attack class.

        Args:
            attack_id: Unique identifier for the attack (e.g., "a01", "a03")

        Returns:
            Decorator function

        Example:
            @OWASPRegistry.register("a01")
            class BrokenAccessControlAttack(BaseOWASPAttack):
                ...
        """
        def decorator(attack_class: Type[BaseOWASPAttack]):
            cls._attacks[attack_id] = attack_class
            return attack_class
        return decorator

    @classmethod
    def get(cls, attack_id: str) -> Optional[Type[BaseOWASPAttack]]:
        """
        Get an OWASP attack class by ID.

        Args:
            attack_id: Unique identifier for the attack

        Returns:
            Attack class if found, None otherwise
        """
        return cls._attacks.get(attack_id)

    @classmethod
    def create(cls, attack_id: str, **config) -> Optional[BaseOWASPAttack]:
        """
        Create an instance of an OWASP attack by ID.

        Args:
            attack_id: Unique identifier for the attack
            **config: Configuration options to pass to the attack

        Returns:
            Attack instance if found, None otherwise
        """
        attack_class = cls.get(attack_id)
        if attack_class:
            instance = attack_class()
            if config:
                instance.configure(**config)
            return instance
        return None

    @classmethod
    def list_attacks(cls) -> List[Dict[str, str]]:
        """
        List all registered OWASP attacks with their info.

        Returns:
            List of attack information dictionaries
        """
        attacks = []
        for attack_id, attack_class in cls._attacks.items():
            instance = attack_class()
            info = instance.get_info()
            info["id"] = attack_id
            attacks.append(info)
        return attacks

    @classmethod
    def get_by_category(cls, category: OWASPCategory) -> List[Dict[str, str]]:
        """
        Get all attacks for a specific OWASP category.

        Args:
            category: OWASPCategory enum value

        Returns:
            List of attack information dictionaries
        """
        attacks = []
        for attack_id, attack_class in cls._attacks.items():
            instance = attack_class()
            if instance.category == category:
                info = instance.get_info()
                info["id"] = attack_id
                attacks.append(info)
        return attacks

    @classmethod
    def get_attack_ids(cls) -> List[str]:
        """
        Get list of all registered OWASP attack IDs.

        Returns:
            List of attack IDs
        """
        return list(cls._attacks.keys())

    @classmethod
    def get_all_categories(cls) -> List[Dict[str, str]]:
        """
        Get all OWASP categories with their registered attacks.

        Returns:
            List of category information with attack counts
        """
        categories = []
        for category in OWASPCategory:
            attacks = cls.get_by_category(category)
            categories.append({
                "id": category.name,
                "name": category.value,
                "attack_count": len(attacks),
                "attacks": [a["id"] for a in attacks]
            })
        return categories

    @classmethod
    def clear(cls) -> None:
        """Clear all registered attacks. Useful for testing."""
        cls._attacks.clear()


# Export commonly used classes
__all__ = [
    "OWASPRegistry",
    "BaseOWASPAttack",
    "OWASPCategory",
    "OWASPTestCase"
]
