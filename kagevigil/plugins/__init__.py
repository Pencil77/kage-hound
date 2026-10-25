"""
Layer 5: Extensible Plugin Architecture.
Enables drop-in custom detectors, verifiers, and threat intelligence scouts.
"""

import importlib.util
from abc import ABC, abstractmethod
from pathlib import Path

from kagevigil.core.models import LeakMatch, SecretMatch, VerificationResult


class BaseDetector(ABC):
    """Abstract base class for custom secret detection plugins."""

    name: str = "custom_detector"

    @abstractmethod
    def scan(self, content: str, file_path: str = "buffer") -> list[SecretMatch]:
        """Inspect content string and return list of detected SecretMatch instances."""


class BaseVerifier(ABC):
    """Abstract base class for custom vendor verifier plugins."""

    name: str = "custom_verifier"

    @abstractmethod
    def verify(self, secret: str) -> VerificationResult:
        """Pings vendor API and returns VerificationResult."""


class BaseScout(ABC):
    """Abstract base class for custom OSINT / darknet scouts."""

    name: str = "custom_scout"

    @abstractmethod
    def query(self, target: str) -> list[LeakMatch]:
        """Queries custom threat source and returns LeakMatch instances."""


def load_plugins_from_directory(dir_path: Path) -> list[BaseDetector]:
    """
    Dynamically load custom detector plugins from a directory.
    """
    detectors: list[BaseDetector] = []
    if not dir_path.is_dir():
        return detectors

    for file_path in dir_path.glob("*.py"):
        if file_path.name.startswith("__"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseDetector)
                        and attr is not BaseDetector
                    ):
                        detectors.append(attr())
        except Exception:
            continue

    return detectors
