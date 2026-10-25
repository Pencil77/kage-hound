"""
HasMySecretLeaked (HMSL) Zero-Knowledge Secret Breach Client.
Uses scrypt hashing to send only a truncated 5-character hash prefix.
Zero plaintext secrets are ever exposed.
"""

import requests

from kagehound.core.hashing import hmsl_hash


class HMSLClient:
    """Zero-knowledge secret breach query client."""

    API_URL = "https://api.hasmysecretleaked.com/v1/hashes/"

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def check_secret(self, secret: str) -> tuple[bool, str]:
        """
        Check if an API key or credential hash exists in the HMSL leak index.
        Returns:
            (is_leaked: bool, status_message: str)
        """
        if not secret:
            return False, "Secret cannot be empty"

        prefix, suffix = hmsl_hash(secret)
        url = f"{self.API_URL}{prefix}"
        headers = {
            "User-Agent": "KageHound-HMSL-Radar/1.0",
            "Accept": "application/json",
        }

        try:
            res = requests.get(url, headers=headers, timeout=self.timeout)
            if res.status_code == 200:
                # API returns list of matching suffix hashes
                data = res.json()
                hashes = data.get("hashes", []) if isinstance(data, dict) else data
                for item in hashes:
                    candidate_suffix = item.get("hash", "") if isinstance(item, dict) else str(item)
                    if candidate_suffix.lower() == suffix:
                        return True, "EXPOSED: Secret found in public breach records (HMSL index)!"
                return False, "CLEAN: Secret was not found in public breach index."
            elif res.status_code == 404:
                return False, "CLEAN: No hashes found matching prefix in HMSL index."
            return False, f"HMSL query returned HTTP {res.status_code}"
        except Exception as e:
            return False, f"Could not reach HMSL service ({e})"
