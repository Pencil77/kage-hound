"""
Intelligence X (IntelX) Threat Radar Client.
Queries paste sites, leaks, and darknet indices via IntelX.
"""

import time

import requests

from kagevigil.core.models import LeakMatch


class IntelXScout:
    """Scouts paste sites and underground dumps using Intelligence X."""

    API_BASE = "https://2.intelx.io"

    def __init__(self, api_key: str | None = None, timeout: int = 10):
        # Default public evaluation key if not configured
        self.api_key = api_key or "00000000-0000-0000-0000-000000000000"
        self.timeout = timeout

    def search(self, target: str, limit: int = 10) -> list[LeakMatch]:
        """
        Execute search on Intelligence X for pastes and data leaks.
        """
        results: list[LeakMatch] = []
        if not target:
            return results

        headers = {
            "x-key": self.api_key,
            "User-Agent": "KageVigil-Scout/1.0",
        }

        # 1. Initiate search job
        try:
            init_res = requests.post(
                f"{self.API_BASE}/intelligent/search",
                json={
                    "term": target,
                    "maxresults": limit,
                    "media": 0,
                    "sort": 2,
                    "terminate": [1],
                },
                headers=headers,
                timeout=self.timeout,
            )
            if init_res.status_code != 200:
                return results

            search_id = init_res.json().get("id")
            if not search_id:
                return results

            # 2. Fetch search results
            time.sleep(1.0)  # Brief pause for results indexing
            res_url = f"{self.API_BASE}/intelligent/search/result"
            params = {"id": search_id, "limit": limit}
            fetch_res = requests.get(res_url, params=params, headers=headers, timeout=self.timeout)

            if fetch_res.status_code == 200:
                data = fetch_res.json()
                records = data.get("records", [])
                for r in records[:limit]:
                    name = r.get("name") or "Paste Record"
                    sys_id = r.get("systemid")
                    url = f"https://intelx.io/?did={sys_id}" if sys_id else "https://intelx.io"
                    snippet = r.get("description") or f"Storage record {r.get('storageid')}"

                    results.append(
                        LeakMatch(
                            source="intelx",
                            target=target,
                            title=name,
                            url=url,
                            snippet=snippet,
                            date_found=r.get("date"),
                        )
                    )

            return results
        except Exception:
            return results
