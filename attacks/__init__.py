"""
Attack module registry.

This module provides a central registry for all attack modules,
allowing dynamic discovery and instantiation of attacks.
"""

from typing import Dict, Type, Optional, List
from attacks.base import BaseAttack, Finding, Severity


class AttackRegistry:
    """
    Registry for managing attack modules.

    Provides methods to register, discover, and instantiate attack modules.
    """

    _attacks: Dict[str, Type[BaseAttack]] = {}

    @classmethod
    def register(cls, attack_id: str):
        """
        Decorator to register an attack class.

        Args:
            attack_id: Unique identifier for the attack

        Returns:
            Decorator function

        Example:
            @AttackRegistry.register("bruteforce")
            class BruteForceAttack(BaseAttack):
                ...
        """

        def decorator(attack_class: Type[BaseAttack]):
            cls._attacks[attack_id] = attack_class
            return attack_class

        return decorator

    @classmethod
    def get(cls, attack_id: str) -> Optional[Type[BaseAttack]]:
        """
        Get an attack class by ID.

        Args:
            attack_id: Unique identifier for the attack

        Returns:
            Attack class if found, None otherwise
        """
        return cls._attacks.get(attack_id)

    @classmethod
    def create(cls, attack_id: str, **config) -> Optional[BaseAttack]:
        """
        Create an instance of an attack by ID.

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
        List all registered attacks with their info.

        Returns:
            List of attack information dictionaries
        """
        attacks = []
        for attack_id, attack_class in cls._attacks.items():
            instance = attack_class()
            attacks.append(
                {
                    "id": attack_id,
                    "name": instance.name,
                    "description": instance.description,
                    "config_options": instance.get_config_options(),
                }
            )
        return attacks

    @classmethod
    def get_attack_ids(cls) -> List[str]:
        """
        Get list of all registered attack IDs.

        Returns:
            List of attack IDs
        """
        return list(cls._attacks.keys())

    @classmethod
    def clear(cls) -> None:
        """Clear all registered attacks. Useful for testing."""
        cls._attacks.clear()


# Export commonly used classes
__all__ = ["AttackRegistry", "BaseAttack", "Finding", "Severity"]
