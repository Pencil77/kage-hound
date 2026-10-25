"""
Data models for KageHound.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def redact(secret: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Safely redact secret string to prevent accidental disclosure."""
    if not secret:
        return "[EMPTY]"
    length = len(secret)
    if length <= 8:
        return "***"
    start = secret[:keep_start]
    end = secret[-keep_end:]
    return f"{start}***{end}"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerificationStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNVERIFIABLE = "UNVERIFIABLE"
    UNTESTED = "UNTESTED"


class Rule(BaseModel):
    id: str
    name: str
    category: str
    severity: Severity = Severity.HIGH
    regex: str
    description: str = ""
    verifier_type: str | None = None


class VerificationResult(BaseModel):
    status: VerificationStatus = VerificationStatus.UNTESTED
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class SecretMatch(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    severity: Severity = Severity.HIGH
    file_path: str
    line_number: int
    raw_secret: str
    redacted_secret: str = ""
    entropy: float | None = None
    verification: VerificationResult = Field(default_factory=VerificationResult)

    def model_post_init(self, __context: Any) -> None:
        if not self.redacted_secret:
            self.redacted_secret = redact(self.raw_secret)


class BreachMatch(BaseModel):
    target: str
    breach_name: str
    breach_date: str | None = None
    pwn_count: int = 0
    description: str = ""
    data_classes: list[str] = Field(default_factory=list)


class LeakMatch(BaseModel):
    source: str
    target: str
    title: str
    url: str
    snippet: str = ""
    date_found: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
