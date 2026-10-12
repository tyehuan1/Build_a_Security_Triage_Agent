"""CISA Known Exploited Vulnerabilities catalog (full JSON feed).

Returns the whole feed; lookup_kev (tool layer) searches it for the CVE.
"""

from sources.base import SourceResult, fetch


def fetch_kev(settings: dict) -> SourceResult:
    url = settings["sources"]["kev"]["url"]
    return fetch("kev", url, settings, cache_accepts=lambda d: isinstance(d.get("vulnerabilities"), list))
