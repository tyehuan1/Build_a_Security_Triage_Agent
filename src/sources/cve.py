"""CVE Program record (CVE JSON 5.x) from the CVE Services API."""

from sources.base import SourceResult, fetch


def fetch_cve(cve_id: str, settings: dict) -> SourceResult:
    url = settings["sources"]["cve"]["url"].format(cve_id=cve_id)

    def covers(data) -> bool:
        return data.get("cveMetadata", {}).get("cveId") == cve_id

    return fetch("cve", url, settings, cache_accepts=covers)
