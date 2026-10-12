"""Fact validation (design workflow step "Fact validation", performed by code).

Checks the model's extracted facts against the raw tool outputs saved on disk by the tool runner,
so a fact the tools never returned cannot reach the rating. Returns a list of problems; empty
means the facts passed. The orchestrator gives the model one retry, then applies P-RV-F.

Checks:
  citations   - every cited call exists in the trace and succeeded; locators point inside that result;
                every asserted (non-null / non-unknown) fact has at least one citation
  asset       - asset fields match the asset record returned by environment_search
  threat      - CVE ID, CVSS vector/score/version and the fixed build match lookup_vulnerability;
                a KB number must appear in some tool result
  exploit     - kev_listed matches lookup_kev; the vendor assessment text appears in a cited result;
                in-the-wild / PoC claims cite a search or KEV result
  impact      - RTO matches a business service linked to the asset
  conditions  - C1/C2/C3 agree with the tool data (C3 must stay "unknown" while the OS build is unknown);
                every unknown condition has a decisive unknown; "conflicting" has a recorded conflict
  plausibility- reachability 2 needs Internet exposure; reachability 0 contradicts a permitted flow to the asset
"""

from __future__ import annotations

import json
import re
from typing import Iterator, Optional

from tools.registry import load_raw_output

SUCCESS = ("found", "not_found")
VENDOR_LIKELY_PHRASES = ("exploitation more likely", "exploitation detected")


# ---------------------------------------------------------------- helpers

def _citations(obj, path="") -> Iterator[tuple[str, dict]]:
    """Yield (json path, citation) for every citation anywhere in the facts."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if k == "citations" and isinstance(v, list):
                for i, c in enumerate(v):
                    yield f"{p}[{i}]", c
            else:
                yield from _citations(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _citations(v, f"{path}[{i}]")


def _version(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


class Evidence:
    """Successful tool results loaded from the saved raw outputs."""

    def __init__(self, trace: list[dict]):
        self.trace = {t["call_id"]: t for t in trace}
        self.results = {cid: load_raw_output(t)["result"] for cid, t in self.trace.items() if t["result_status"] in SUCCESS}

    def of_tool(self, tool: str) -> list[tuple[str, dict]]:
        return [(cid, r) for cid, r in self.results.items() if self.trace[cid]["tool"] == tool]

    def latest(self, tool: str) -> Optional[dict]:
        found = self.of_tool(tool)
        return found[-1][1] if found else None

    def env_records(self, record_type: str) -> list[tuple[str, dict]]:
        return [(cid, rec) for cid, r in self.of_tool("environment_search") for rec in r.get("records", [])
                if rec["record_type"] == record_type]

    def asset(self, asset_id: str) -> Optional[dict]:
        return next((rec["data"] for _, rec in self.env_records("asset") if rec["record_id"] == asset_id), None)

    def text(self, call_ids=None) -> str:
        ids = call_ids if call_ids is not None else self.results.keys()
        return json.dumps([self.results[c] for c in ids if c in self.results], ensure_ascii=False).lower()


def _locator_ok(cit: dict, tool: str, result: dict) -> bool:
    # The model sees each result wrapped as {"call_id", ..., "result": {...}}, so accept a "result." prefix.
    loc = re.sub(r"^result\.", "", cit["locator"])
    if tool == "environment_search":
        refs = {r["locator"] for r in result.get("records", [])} | {r["record_id"] for r in result.get("records", [])}
        cov = result.get("coverage") or {}
        refs |= {"coverage", cov.get("completeness_locator") or "coverage"}
        return any(ref and ref in loc for ref in refs)
    if any(loc.startswith(p) for p in ("cve:", "nvd:")):
        return True
    head = re.split(r"[.\[\s(]", loc, maxsplit=1)[0]
    return head in result


# ---------------------------------------------------------------- checks

def check_citations(facts: dict, ev: Evidence) -> list[str]:
    problems = []
    for path, c in _citations(facts):
        cid = c["call_id"]
        t = ev.trace.get(cid)
        if t is None:
            problems.append(f"{path}: cites {cid}, which is not a tool call in this run")
        elif t["result_status"] not in SUCCESS:
            problems.append(f"{path}: cites {cid}, which returned {t['result_status']} and has no evidence")
        elif not _locator_ok(c, t["tool"], ev.results[cid]):
            problems.append(f"{path}: locator '{c['locator']}' does not point inside {cid} ({t['tool']})")

    def need(block: dict, path: str, asserted: bool):
        if asserted and not block.get("citations"):
            problems.append(f"{path}: asserts a value but has no citations")

    need(facts["asset"], "asset", facts["asset"].get("operating_system") is not None)
    need(facts["scope_check"], "scope_check", True)
    if facts["scope_check"]["citations"] and not any(
            ev.trace.get(c["call_id"], {}).get("tool") == "environment_search" for c in facts["scope_check"]["citations"]):
        problems.append("scope_check: must cite an environment_search result (the coverage of other assets)")
    need(facts["threat"], "threat", bool(facts["threat"].get("fix", {}).get("fixed_build")))
    need(facts["technical_severity"], "technical_severity", facts["technical_severity"].get("vector") is not None)
    for c in facts["conditions"]:
        need(c, f"conditions[{c['id']}]", c["result"] in ("true", "false", "conflicting"))
    need(facts["likelihood"]["reachability"], "likelihood.reachability", facts["likelihood"]["reachability"]["value"] is not None)
    ea = facts["likelihood"]["exploit_activity"]
    need(ea, "likelihood.exploit_activity",
         any(ea[k] is not None for k in ("kev_listed", "credible_in_the_wild", "public_poc", "vendor_exploitation_likely")))
    for k in ("asset_criticality", "blast_radius", "rto_hours"):
        need(facts["impact"][k], f"impact.{k}", facts["impact"][k]["value"] is not None)
    return problems


def check_asset(facts: dict, ev: Evidence, intake: dict) -> list[str]:
    a = facts["asset"]
    if a["asset_id"] != intake["asset_id"]:
        return [f"asset.asset_id is {a['asset_id']!r}; the assessed asset is {intake['asset_id']!r}"]
    rec = ev.asset(intake["asset_id"])
    if rec is None:
        asserted = [k for k in ("operating_system", "os_build", "network_zone", "tier", "host_count") if a.get(k) is not None]
        return [f"asset fields {asserted} are asserted but no environment_search result contains asset {intake['asset_id']}"] if asserted else []
    expected = {"operating_system": rec["platform"]["os"], "os_build": rec["platform"]["os_build"], "network_zone": rec["zone"],
                "tier": rec["tier"], "host_count": rec["count"]}
    problems = [f"asset.{k} is {a.get(k)!r} but the environment record has {v!r}" for k, v in expected.items() if a.get(k) != v]
    if set(a["services"]) != set(rec["services"]):
        problems.append(f"asset.services {a['services']} != environment record {rec['services']}")
    return problems


def _fixed_build_for(vuln: dict, os_name: Optional[str]) -> Optional[str]:
    return next((x["fixed_build"] for x in vuln.get("affected", []) if os_name and x["product"] == os_name), None)


def check_threat(facts: dict, ev: Evidence, intake: dict) -> list[str]:
    problems = []
    th, ts = facts["threat"], facts["technical_severity"]
    if th["cve_id"] != intake["cve_id"]:
        problems.append(f"threat.cve_id is {th['cve_id']!r}; the assessed CVE is {intake['cve_id']!r}")
    vuln = ev.latest("lookup_vulnerability")
    if vuln is None:
        if ts.get("vector") or th["fix"].get("fixed_build"):
            problems.append("CVSS / fixed build are asserted but lookup_vulnerability did not succeed")
        return problems
    cvss = vuln.get("cvss") or {}
    for k_fact, k_tool in (("vector", "vector"), ("base_score", "base_score"), ("cvss_version", "version")):
        if ts.get(k_fact) != cvss.get(k_tool):
            problems.append(f"technical_severity.{k_fact} is {ts.get(k_fact)!r} but lookup_vulnerability returned {cvss.get(k_tool)!r}")
    expected_fix = _fixed_build_for(vuln, facts["asset"].get("operating_system"))
    if th["fix"].get("fixed_build") != expected_fix:
        problems.append(f"threat.fix.fixed_build is {th['fix'].get('fixed_build')!r} but lookup_vulnerability reports "
                        f"{expected_fix!r} for {facts['asset'].get('operating_system')!r}")
    kb = th["fix"].get("kb")
    if kb and kb.lower() not in ev.text():
        problems.append(f"threat.fix.kb {kb!r} does not appear in any tool result")
    return problems


def check_exploit_activity(facts: dict, ev: Evidence) -> list[str]:
    problems = []
    ea = facts["likelihood"]["exploit_activity"]
    kev = ev.latest("lookup_kev")
    expected = kev["in_kev"] if kev else None
    if ea["kev_listed"] != expected:
        problems.append(f"exploit_activity.kev_listed is {ea['kev_listed']!r} but lookup_kev returned in_kev={expected!r}")
    cited = [c["call_id"] for c in ea["citations"]]
    cited_text = ev.text(cited)
    if ea["vendor_exploitation_likely"] and not any(p in cited_text for p in VENDOR_LIKELY_PHRASES):
        problems.append("vendor_exploitation_likely is true but no cited result contains a vendor 'Exploitation More Likely/Detected' rating")
    va = ea.get("vendor_exploitability_assessment")
    if va and va.lower() not in ev.text():
        problems.append(f"vendor_exploitability_assessment {va!r} does not appear in any tool result")
    search_or_kev = {c for c in cited if ev.trace.get(c, {}).get("tool") in ("tavily_search", "lookup_kev")}
    for k in ("credible_in_the_wild", "public_poc"):
        if ea[k] and not search_or_kev:
            problems.append(f"exploit_activity.{k} is true but no tavily_search or lookup_kev result is cited")
    return problems


def check_impact(facts: dict, ev: Evidence, intake: dict) -> list[str]:
    rto = facts["impact"]["rto_hours"]["value"]
    if rto is None:
        return []
    rec = ev.asset(intake["asset_id"])
    linked = set(rec.get("business_services", [])) if rec else set()
    services = [r["data"] for _, r in ev.env_records("business_service")
                if r["record_id"] in linked or intake["asset_id"] in r["data"].get("supporting_assets", [])]
    if not services:
        return [f"impact.rto_hours is {rto} but no business service linked to {intake['asset_id']} was returned by environment_search"]
    if rto not in [s.get("rto_hours") for s in services]:
        return [f"impact.rto_hours is {rto} but linked business services have RTO {[s.get('rto_hours') for s in services]}"]
    return []


def check_conditions(facts: dict, ev: Evidence, intake: dict, settings: dict) -> list[str]:
    problems = []
    cond = {c["id"]: c["result"] for c in facts["conditions"]}
    if set(cond) != {"C1", "C2", "C3"}:
        return [f"conditions must be exactly C1, C2, C3; got {sorted(cond)}"]
    rec = ev.asset(intake["asset_id"])
    vuln = ev.latest("lookup_vulnerability")
    os_name = rec["platform"]["os"] if rec else None
    products = [x["product"] for x in vuln.get("affected", [])] if vuln else []

    def expect(cid: str, value: Optional[str], why: str):
        if value is not None and cond[cid] != value and cond[cid] != "conflicting":
            problems.append(f"{cid} is '{cond[cid]}' but the tool data gives '{value}' ({why})")

    if rec and vuln:
        expect("C1", "true" if os_name in products else "false", f"asset OS {os_name!r} vs affected products")
    elif cond["C1"] in ("true", "false"):
        problems.append(f"C1 is '{cond['C1']}' without both the asset record and lookup_vulnerability results")
    if rec:
        svc = settings["inputs"]["vulnerable_service"]
        expect("C2", "true" if svc in rec["services"] else "false", f"'{svc}' in asset services {rec['services']}")
        build, fixed = rec["platform"]["os_build"], _fixed_build_for(vuln, os_name) if vuln else None
        if build is None:
            expect("C3", "unknown", "the asset's os_build is null (unknown)")
        elif fixed:
            expect("C3", "true" if _version(build) < _version(fixed) else "false", f"build {build} vs fixed {fixed}")
    else:
        for cid in ("C2", "C3"):
            if cond[cid] in ("true", "false"):
                problems.append(f"{cid} is '{cond[cid]}' but no environment_search result contains asset {intake['asset_id']}")

    decisive = {u.get("condition_id") for u in facts["unknowns"] if u["decisive"]}
    for cid, v in cond.items():
        if v == "unknown" and cid not in decisive:
            problems.append(f"{cid} is unknown but no decisive unknown with condition_id {cid} is listed")
        if v == "conflicting" and not facts["conflicts"] and not (vuln and vuln.get("conflicts")):
            problems.append(f"{cid} is conflicting but no conflict is recorded")
    return problems


def check_plausibility(facts: dict, ev: Evidence, intake: dict) -> list[str]:
    problems = []
    reach = facts["likelihood"]["reachability"]["value"]
    rec = ev.asset(intake["asset_id"])
    if reach == 2 and rec and rec.get("internet_exposure") == "none":
        problems.append(f"reachability is 2 (Internet-facing) but {intake['asset_id']}.internet_exposure is 'none'")
    flows_to_asset = [r for _, r in ev.env_records("flow") if intake["asset_id"] in str(r["data"].get("destination", ""))]
    if reach == 0 and flows_to_asset:
        problems.append(f"reachability is 0 (isolated) but permitted flows reach {intake['asset_id']}: "
                        f"{[r['record_id'] for r in flows_to_asset]}")
    return problems


def validate_facts(facts: dict, trace: list[dict], intake: dict, settings: dict) -> list[str]:
    ev = Evidence(trace)
    problems = []
    for check in (lambda: check_citations(facts, ev), lambda: check_asset(facts, ev, intake),
                  lambda: check_threat(facts, ev, intake), lambda: check_exploit_activity(facts, ev),
                  lambda: check_impact(facts, ev, intake), lambda: check_conditions(facts, ev, intake, settings),
                  lambda: check_plausibility(facts, ev, intake)):
        problems += check()
    return problems
