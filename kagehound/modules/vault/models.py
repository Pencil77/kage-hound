"""
Data models for Vault Integration with Zero-Leakage Guarantees.
Raw secret values are strictly sequestered in-memory and never serialized or exposed.
"""

import hashlib

from pydantic import BaseModel

from kagehound.core.models import VerificationStatus, redact


class VaultSecretRef:
    """
    In-memory reference to a vault secret.
    Calculates non-reversible fingerprints and strictly redacts any string representations.
    """

    def __init__(self, key_name: str, raw_secret: str):
        self.key_name = key_name
        self._raw_secret = raw_secret
        self.length = len(raw_secret)
        self.redacted = redact(raw_secret)
        self.sha256 = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

    @property
    def raw_secret(self) -> str:
        """Access raw secret only in-memory for matching."""
        return self._raw_secret

    def __repr__(self) -> str:
        return f"<VaultSecretRef key='{self.key_name}' length={self.length} redacted='{self.redacted}'>"

    def __str__(self) -> str:
        return self.__repr__()


class VaultLeakFinding(BaseModel):
    """Represents a discovered leak of a vault secret in a file or git tree."""

    variable_name: str
    file_path: str
    line_number: int
    redacted_snippet: str
    severity: str = "CRITICAL"


class VaultBreachFinding(BaseModel):
    """Represents a vault secret matching a public leak/breach dataset."""

    variable_name: str
    breach_source: str
    status_message: str
    occurrence_count: int = 0
    severity: str = "HIGH"


class VaultLivenessFinding(BaseModel):
    """Represents the active live status of a vault secret."""

    variable_name: str
    service_type: str
    status: VerificationStatus
    details: str = ""
