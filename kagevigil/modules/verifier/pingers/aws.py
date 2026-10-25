"""
AWS & OCI credential verifiers.
"""

import re

from kagevigil.core.models import VerificationResult, VerificationStatus


def verify_aws(key_id: str, timeout: int = 5) -> VerificationResult:
    """
    AWS Key validation.
    Note: Full STS verification requires both Key ID and Secret Access Key.
    Here we validate AWS key format, prefix structure, and length.
    """
    if re.match(r"^(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}$", key_id):
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message="Valid AWS Access Key ID format (Secret key required for STS:GetCallerIdentity).",
            details={"key_type": key_id[:4]},
        )
    return VerificationResult(
        status=VerificationStatus.INACTIVE,
        message="Malformed AWS Access Key ID.",
    )


def verify_oci(identifier: str, timeout: int = 5) -> VerificationResult:
    """Validate Oracle Cloud OCID structure."""
    if re.match(
        r"^ocid1\.(?:user|tenancy|instance|compartment)\.oc1\.[a-z0-9]+\.[a-z0-9]{40,}$", identifier
    ):
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message="Valid OCI OCID resource identifier (Private key signature required for API test).",
        )
    return VerificationResult(
        status=VerificationStatus.INACTIVE,
        message="Malformed OCI OCID format.",
    )
