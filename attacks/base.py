"""
Base attack module providing abstract classes and data structures for all attacks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Generator, Dict, Any, Optional
from datetime import datetime


class Severity(Enum):
    """Severity levels for security findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Represents a security finding discovered during an attack."""
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


class BaseAttack(ABC):
    """
    Abstract base class for all attack modules.
    
    All attack implementations must inherit from this class and implement
    the required abstract methods.
    """
    
    name: str = "Base Attack"
    description: str = "Base attack class - do not use directly"
    
    def __init__(self):
        self._progress: float = 0.0
        self._is_running: bool = False
        self._is_cancelled: bool = False
        self._config: Dict[str, Any] = {}
        self._findings: list[Finding] = []
    
    @abstractmethod
    def configure(self, **kwargs) -> None:
        """
        Configure attack parameters.
        
        Args:
            **kwargs: Attack-specific configuration options
        """
        pass
    
    @abstractmethod
    def run(self, target: str) -> Generator[Finding, None, None]:
        """
        Execute the attack and yield findings.
        
        Args:
            target: The target URL or IP address
            
        Yields:
            Finding: Security findings discovered during the attack
        """
        pass
    
    def get_progress(self) -> float:
        """
        Return progress as percentage (0-100).
        
        Returns:
            float: Current progress percentage
        """
        return self._progress
    
    def set_progress(self, progress: float) -> None:
        """
        Set the current progress.
        
        Args:
            progress: Progress value between 0 and 100
        """
        self._progress = max(0.0, min(100.0, progress))
    
    def is_running(self) -> bool:
        """Check if the attack is currently running."""
        return self._is_running
    
    def cancel(self) -> None:
        """Request cancellation of the running attack."""
        self._is_cancelled = True
    
    def is_cancelled(self) -> bool:
        """Check if cancellation has been requested."""
        return self._is_cancelled
    
    def reset(self) -> None:
        """Reset attack state for a new run."""
        self._progress = 0.0
        self._is_running = False
        self._is_cancelled = False
        self._findings = []
    
    def get_config(self) -> Dict[str, Any]:
        """Get the current configuration."""
        return self._config.copy()
    
    def get_findings(self) -> list[Finding]:
        """Get all findings from the last run."""
        return self._findings.copy()
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self._findings.append(finding)
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get attack module information.
        
        Returns:
            dict: Attack name, description, and configuration options
        """
        return {
            "name": self.name,
            "description": self.description,
            "config_options": self.get_config_options()
        }
    
    def get_config_options(self) -> Dict[str, Any]:
        """
        Get available configuration options for this attack.
        
        Override in subclasses to define attack-specific options.
        
        Returns:
            dict: Configuration options with their types and defaults
        """
        return {}
