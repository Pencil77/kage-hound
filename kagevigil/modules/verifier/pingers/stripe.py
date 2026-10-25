"""
Stripe API key verifier.
Pings https://api.stripe.com/v1/balance
"""

import requests

from kagevigil.core.models import VerificationResult, VerificationStatus


def verify_stripe(key: str, timeout: int = 5) -> VerificationResult:
    """Validate Stripe secret/publishable key."""
    if key.startswith("pk_"):
        # Publishable key check
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message="Publishable keys are public by design; skipping balance verification.",
        )

    url = "https://api.stripe.com/v1/balance"
    headers = {"Authorization": f"Bearer {key}"}
    try:
        res = requests.get(url, headers=headers, timeout=timeout)
        if res.status_code == 200:
            return VerificationResult(
                status=VerificationStatus.ACTIVE,
                message="Verified ACTIVE Stripe key (Authorized for account balance API).",
            )
        elif res.status_code == 401:
            return VerificationResult(
                status=VerificationStatus.INACTIVE,
                message="Stripe key is invalid or revoked (HTTP 401).",
            )
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"Stripe response: HTTP {res.status_code}",
        )
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            message=f"Network error verifying Stripe key: {e}",
        )
