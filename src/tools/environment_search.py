"""environment_search: query the Northbridge environment snapshot (simulated JSON).

Contract (design doc):
  in : {"query_type": asset|text|flows|business_service, "query": str, "max_results": int}
  out: {status: found|not_found|failed, records[{record_type, record_id, locator, basis, evidence_ids,
        matched_on, unknown_fields, data}], source, retrieved_at, locator, mode: "simulated"}
record_type values follow the design list; "data_asset", "organization" and "global_unknown" are
added so every part of the file is searchable.

asset and text queries also return a coverage block (how many assets were searched, which matched,
and the S06 completeness statement) so the agent can support "no other asset runs X".
File existence and validity are checked at intake; this tool only reads the parsed snapshot.
"""

from __future__ import annotations

import json
from datetime import datetime

from tools.base import ToolOutput

SOURCE = "windows_enterprise_environment_json"

# (collection, id field, record_type), in the order results are returned for text queries.
COLLECTIONS = [
    ("assets", "asset_id", "asset"),
    ("flows", "flow_id", "flow"),
    ("business_services", "service_id", "business_service"),
    ("zones", "zone_id", "zone"),
    ("controls", "control_id", "control"),
    ("absences", None, "absence"),
    ("denied_paths", None, "denied_path"),
    ("evidence", "evidence_id", "scenario_evidence"),
    ("data_assets", "data_id", "data_asset"),
    ("global_unknowns", "id", "global_unknown"),
]


# ---------------------------------------------------------------- record helpers

def _null_paths(obj, prefix="") -> list[str]:
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            out += [p] if v is None else _null_paths(v, p)
    return out


def _basis(rec: dict) -> str:
    vals = {str(v).split(" ")[0] for k, v in rec.items() if (k == "basis" or k.endswith("_basis")) and isinstance(v, str)}
    vals = {"stated" if v.startswith(("stated", "explicit")) else "inferred" if v.startswith("inferred") else v for v in vals}
    if vals <= {"stated"}:
        return "stated"
    if vals <= {"inferred"}:
        return "inferred"
    return "mixed"


def _matched_on(obj, terms: list[str], prefix="") -> list[str]:
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _matched_on(v, terms, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _matched_on(v, terms, f"{prefix}[{i}]")
    elif obj is not None and any(t in str(obj).lower() for t in terms):
        out.append(f"{prefix}: {str(obj)[:80]}")
    return out


def _record(rtype: str, rid: str, locator: str, rec: dict, terms: list[str] | None = None) -> dict:
    ev = rec.get("evidence_ids") or ([rec["evidence_id"]] if "evidence_id" in rec else [])
    return {
        "record_type": rtype,
        "record_id": rid,
        "locator": locator,
        "basis": _basis(rec),
        "evidence_ids": ev,
        "matched_on": _matched_on(rec, terms) if terms else [],
        "unknown_fields": _null_paths(rec),
        "data": rec,
    }


def _iter_records(env: dict):
    """Yield (record_type, record_id, locator, record) for every searchable record."""
    for coll, idf, rtype in COLLECTIONS:
        for i, rec in enumerate(env.get(coll, [])):
            rid = rec[idf] if idf else f"{coll}[{i}]"
            loc = f"{coll}[{idf}={rid}]" if idf else f"{coll}[{i}]"
            yield rtype, rid, loc, rec
    net = env.get("network", {})
    if net:
        yield "network_policy", "network.default_policy", "network.default_policy", {
            **net["default_policy"], "internet_path": net.get("internet_path")}
        yield "public_exposure", "network.public_services", "network.public_services; network.not_published_to_internet", {
            "public_services": net.get("public_services"), "not_published_to_internet": net.get("not_published_to_internet"),
            "not_published_notes": net.get("not_published_notes"), "exposure_note": net.get("exposure_note"),
            "evidence_ids": net.get("evidence_ids", [])}
    if env.get("organization"):
        yield "organization", "organization", "organization", env["organization"]


def _coverage(env: dict, matching_ids: list[str]) -> dict:
    s06 = next((e for e in env.get("evidence", []) if e["evidence_id"] == "S06"), None)
    return {
        "assets_searched": len(env.get("assets", [])),
        "matching_asset_ids": matching_ids,
        "completeness_statement": s06["facts"][0] if s06 else None,
        "completeness_limitations": s06["limitations"] if s06 else None,
        "completeness_locator": "evidence[evidence_id=S06]" if s06 else None,
    }


def _terms(query: str) -> list[str]:
    return [t for t in query.lower().split() if t]


def _contains_all(rec: dict, terms: list[str]) -> bool:
    blob = json.dumps(rec, ensure_ascii=False).lower()
    return all(t in blob for t in terms)


# ---------------------------------------------------------------- query types

def _q_asset(env, q, terms):
    ql = q.strip().lower()
    hits = []
    for a in env.get("assets", []):
        if a["asset_id"].lower() == ql or ql in a["name"].lower() or ql in [t.lower() for t in a.get("tags", [])]:
            hits.append(_record("asset", a["asset_id"], f"assets[asset_id={a['asset_id']}]", a, terms))
    return hits, _coverage(env, [h["record_id"] for h in hits])


def _q_text(env, q, terms):
    hits = [_record(rt, rid, loc, rec, terms) for rt, rid, loc, rec in _iter_records(env) if _contains_all(rec, terms)]
    return hits, _coverage(env, [h["record_id"] for h in hits if h["record_type"] == "asset"])


def _q_flows(env, q, terms):
    hits = []
    for rt, rid, loc, rec in _iter_records(env):
        if rt in ("flow", "denied_path"):
            ends = " ".join(str(rec.get(k, "")) for k in ("source", "destination", "service")).lower()
            if all(t in ends for t in terms):
                hits.append(_record(rt, rid, loc, rec, terms))
        elif rt == "zone" and any(t.upper() in rec.get("assets", []) or t == rec["zone_id"].lower() for t in terms):
            hits.append(_record(rt, rid, loc, rec, terms))
    # Perimeter policy and published services always accompany a flow query (reachability context).
    hits += [_record(rt, rid, loc, rec) for rt, rid, loc, rec in _iter_records(env) if rt in ("network_policy", "public_exposure")]
    return hits, None


def _q_business_service(env, q, terms):
    ql = q.strip().lower()
    asset_bs = {bs for a in env.get("assets", []) if a["asset_id"].lower() == ql for bs in a.get("business_services", [])}
    hits = []
    for b in env.get("business_services", []):
        if (b["service_id"].lower() == ql or ql in b["name"].lower() or b["service_id"] in asset_bs
                or ql in [s.lower() for s in b.get("supporting_assets", [])]):
            hits.append(_record("business_service", b["service_id"], f"business_services[service_id={b['service_id']}]", b, terms))
    return hits, None


QUERY_TYPES = {"asset": _q_asset, "text": _q_text, "flows": _q_flows, "business_service": _q_business_service}


def run(args: dict, env: dict, env_path: str) -> ToolOutput:
    qtype, query, limit = args["query_type"], args["query"], args.get("max_results", 10)
    terms = _terms(query)
    hits, coverage = QUERY_TYPES[qtype](env, query, terms)
    truncated = max(0, len(hits) - limit)
    records = hits[:limit]
    status = "found" if records else "not_found"
    result = {
        "status": status,
        "query_type": qtype,
        "query": query,
        "records": records,
        "total_matches": len(hits),
        "truncated": truncated,
        "coverage": coverage,
        "source": SOURCE,
        "url_or_path": env_path,
        "retrieved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "locator": "; ".join(r["locator"] for r in records),
        "mode": "simulated",
        "conventions": env.get("metadata", {}).get("conventions", {}).get("null"),
    }
    summary = f"{qtype} '{query}': {len(hits)} match(es)" + (f", {truncated} truncated" if truncated else "")
    if coverage:
        summary += f"; matching assets {coverage['matching_asset_ids']} of {coverage['assets_searched']}"
    return ToolOutput(result, status, "simulated", 1, False, summary)
