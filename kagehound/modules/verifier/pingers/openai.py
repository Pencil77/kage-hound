"""
OpenAI API key verifier.
Pings https://api.openai.com/v1/models
"""

import requests

from kagehound.core.models import VerificationResult, VerificationStatus


def verify_openai(key: str, timeout: int = 5) -> VerificationResult:
    """Validate OpenAI API key."""
    url = "https://api.openai.com/v1/models"
    headers = {"Authorization": f"Bearer {key}"}
    try:
        res = requests.get(url, headers=headers, timeout=timeout)
        if res.status_code == 200:
            return VerificationResult(
                status=VerificationStatus.ACTIVE,
                message="Verified ACTIVE OpenAI API key (Models endpoint accessible).",
            )
        elif res.status_code == 401:
            return VerificationResult(
                status=VerificationStatus.INACTIVE,
                message="OpenAI key is invalid or revoked (HTTP 401).",
            )
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"OpenAI response: HTTP {res.status_code}",
        )
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"Network error verifying OpenAI key: {e}",
        )
