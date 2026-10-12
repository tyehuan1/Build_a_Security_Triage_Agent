"""NIST NVD record from the NVD CVE API 2.0."""

from sources.base import SourceResult, fetch


def _cve_ids(data) -> list[str]:
    return [v["cve"]["id"] for v in data.get("vulnerabilities", [])]


def fetch_nvd(cve_id: str, settings: dict) -> SourceResult:
    url = settings["sources"]["nvd"]["url"].format(cve_id=cve_id)
    res = fetch("nvd", url, settings, cache_accepts=lambda d: cve_id in _cve_ids(d))
    # NVD answers an unknown CVE with HTTP 200 and totalResults = 0.
    if res.ok and cve_id not in _cve_ids(res.data):
        res.status = "not_found"
    return res
