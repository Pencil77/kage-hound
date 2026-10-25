"""
Unified Dark Web and Paste Threat Scout Coordinator.
"""

from kagehound.core.models import LeakMatch
from kagehound.modules.darkweb.ahmia import AhmiaScout
from kagehound.modules.darkweb.intelx import IntelXScout
from kagehound.modules.darkweb.paste_scout import PasteScout


class ThreatScoutCoordinator:
    """Coordinates OSINT searches across dark web and public paste feeds."""

    def __init__(self, intelx_api_key: str | None = None, timeout: int = 10):
        self.ahmia = AhmiaScout(timeout=timeout)
        self.intelx = IntelXScout(api_key=intelx_api_key, timeout=timeout)
        self.pastes = PasteScout(timeout=timeout)

    def scout(
        self,
        target: str,
        sources: list[str] | None = None,
        limit_per_source: int = 10,
    ) -> list[LeakMatch]:
        """
        Query specified threat sources and return combined leak matches.
        """
        active_sources = [s.strip().lower() for s in (sources or ["ahmia", "intelx", "pastes"])]
        all_results: list[LeakMatch] = []
        seen_urls = set()

        if "ahmia" in active_sources:
            try:
                for match in self.ahmia.search(target, limit=limit_per_source):
                    if match.url not in seen_urls:
                        seen_urls.add(match.url)
                        all_results.append(match)
            except Exception:
                pass

        if "intelx" in active_sources:
            try:
                for match in self.intelx.search(target, limit=limit_per_source):
                    if match.url not in seen_urls:
                        seen_urls.add(match.url)
                        all_results.append(match)
            except Exception:
                pass

        if "pastes" in active_sources:
            try:
                for match in self.pastes.search_pastes(target, limit=limit_per_source):
                    if match.url not in seen_urls:
                        seen_urls.add(match.url)
                        all_results.append(match)
            except Exception:
                pass

        return all_results
