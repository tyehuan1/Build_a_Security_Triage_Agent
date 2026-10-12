"""lookup_kev: is the CVE in the CISA Known Exploited Vulnerabilities catalog?

Contract (design doc):
  in : {"cve_id": str}
  out: {status: found|not_found|failed, in_kev, date_added, known_ransomware_use, required_action,
        due_date, source_url, retrieved_at, mode: live|cached}
Role: in_kev = true sets exploit activity to 2. Absence from KEV does not establish safety.
On failure: retry once, then the cached feed; with no cache, status=failed and in_kev=null.
"""

from __future__ import annotations

from sources import fetch_kev
from tools.base import ToolOutput, receipt_of


def run(args: dict, settings: dict) -> ToolOutput:
    cve_id = args["cve_id"]
    res = fetch_kev(settings)
    receipts = [receipt_of(res)]
    base = {"cve_id": cve_id, "source_url": res.cite_url, "retrieved_at": res.retrieved_at, "mode": res.mode}
    if res.mode == "cached":
        base["cache_path"] = res.receipt.get("cache_path")

    if not res.ok:
        result = {"status": "failed", "in_kev": None, "date_added": None, "known_ransomware_use": None,
                  "required_action": None, "due_date": None, **base}
        return ToolOutput(result, "failed", None, max(res.attempts, 1), res.status == "failed", f"KEV lookup failed: {res.error}",
                          res.error, receipts)

    feed = res.data
    entry = next((v for v in feed["vulnerabilities"] if v.get("cveID") == cve_id), None)
    catalog = {"catalog_version": feed.get("catalogVersion"), "date_released": feed.get("dateReleased"), "count": feed.get("count")}
    result = {
        "status": "found" if entry else "not_found",
        "in_kev": entry is not None,
        "date_added": entry and entry.get("dateAdded"),
        "known_ransomware_use": entry and entry.get("knownRansomwareCampaignUse"),
        "required_action": entry and entry.get("requiredAction"),
        "due_date": entry and entry.get("dueDate"),
        **base,
        "catalog": catalog,
        "fallback_reason": res.fallback_reason,
        "locator": f"vulnerabilities[cveID={cve_id}]" + ("" if entry else " (no match)"),
        "note": None if entry else "Absence from KEV does not establish that the CVE is not exploited.",
    }
    summary = f"{cve_id} {'IS' if entry else 'is not'} in KEV (catalog {catalog['catalog_version']}, {res.mode})"
    # Save the catalog metadata and the matching entry, not the whole 1.7 MB feed; the receipt holds the feed hash.
    return ToolOutput(result, result["status"], res.mode, max(res.attempts, 1), res.mode == "cached", summary, None, receipts,
                      source_raw={"kev_catalog": catalog, "kev_entry": entry})
