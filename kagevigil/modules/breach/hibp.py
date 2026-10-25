"""
HaveIBeenPwned k-Anonymity Pwned Passwords Client.
Zero plaintext passwords are ever transmitted. Only the first 5 hex chars of SHA-1 are sent.
"""

import requests

from kagevigil.core.hashing import hibp_hash


class HIBPClient:
    """Zero-knowledge password breach lookup via HaveIBeenPwned API."""

    API_URL = "https://api.pwnedpasswords.com/range/"

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def check_password(self, password: str) -> tuple[bool, int]:
        """
        Check if password has appeared in historical data breaches.
        Returns:
            (is_pwned: bool, breach_occurrence_count: int)
        """
        if not password:
            return False, 0

        prefix, suffix = hibp_hash(password)
        url = f"{self.API_URL}{prefix}"
        headers = {
            "User-Agent": "KageVigil-Breach-Radar/1.0",
            # Request padded responses to thwart side-channel packet length analysis
            "Add-Padding": "true",
        }

        try:
            res = requests.get(url, headers=headers, timeout=self.timeout)
            if res.status_code != 200:
                return False, 0

            # Each returned line is formatted: SUFFIX:COUNT
            for line in res.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2:
                    returned_suffix, count_str = parts[0], parts[1]
                    if returned_suffix.upper() == suffix:
                        try:
                            count = int(count_str)
                            return True, count
                        except ValueError:
                            return True, 1
            return False, 0
        except Exception:
            return False, 0
