"""Assemble the assessment JSON (design workflow step "Assemble and Save", performed by code).

Inputs: validated facts (model, checked by factcheck.py), the policy result (policy.py), the
explanation (model), the tool trace and run metadata. Code, not the model, creates every evidence
item: the model's citations {call_id, locator, fact} become E1, E2, ... and the source name, type,
URL, dates, retrieval time and live/cached/simulated label are copied from the saved tool output.
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlparse

from tools.registry import load_raw_output

CONDITION_TEXT = {
    "C1": "The OS is in the affected products list",
    "C2": "The {service} service is installed",
    "C3": "The OS build is below the fixed build{fixed}",
}
ADJ_RULES = {
    "ADJ-RTO": "RTO <= 4 hours raises impact one level",
    "ADJ-CIA": "All CVSS C/I/A Low or None lowers impact one level",
}
EXPLOITABILITY_RULE = "0 = AV:L/P; 1 = AV:N/A otherwise; 2 = AV:N/A with AC:L, PR:N, UI:N"


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _date(value):
    return value[:10] if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}", value) else None


# ---------------------------------------------------------------- evidence

class EvidenceBuilder:
    def __init__(self, trace: list[dict]):
        self.trace = {t["call_id"]: t for t in trace}
        self.raw = {}
        self.items: list[dict] = []
        self._ids: dict[tuple, str] = {}

    def _result(self, call_id: str) -> dict:
        if call_id not in self.raw:
            self.raw[call_id] = load_raw_output(self.trace[call_id])["result"]
        return self.raw[call_id]

    def ids(self, citations: list[dict]) -> list[str]:
        """Evidence IDs for a list of citations, creating evidence items on first use."""
        out = []
        for c in citations or []:
            c = {**c, "locator": re.sub(r"^result\.", "", c["locator"])}
            key = (c["call_id"], c["locator"])
            if key not in self._ids:
                eid = f"E{len(self.items) + 1}"
                self._ids[key] = eid
                self.items.append(self._item(eid, c))
            if self._ids[key] not in out:
                out.append(self._ids[key])
        return out

    def _item(self, eid: str, c: dict) -> dict:
        t = self.trace[c["call_id"]]
        r = self._result(c["call_id"])
        base = {"evidence_id": eid, "fact": c["fact"], "locator": c["locator"], "tool_call_id": c["call_id"],
                "published_date": None, "last_modified_date": None, "fallback_reason": None}
        tool = t["tool"]
        if tool == "environment_search":
            rec = next((x for x in r.get("records", []) if x["locator"] in c["locator"] or x["record_id"] in c["locator"]), None)
            scen = sorted({e for e in (rec or {}).get("evidence_ids", []) if re.match(r"^S\d{2}$", e)})
            if "S06" in c["locator"] or "coverage" in c["locator"]:
                scen = sorted(set(scen) | {"S06"})
            item = {**base, "source_name": "Northbridge environment via environment_search", "source_type": "environment_snapshot",
                    "url_or_path": r["url_or_path"], "retrieved_at": r["retrieved_at"], "retrieval_mode": "simulated"}
            if scen:
                item["scenario_evidence_ids"] = scen
            return item
        if tool == "lookup_kev":
            return {**base, "source_name": "CISA KEV via lookup_kev", "source_type": "kev", "url_or_path": r["source_url"],
                    "retrieved_at": r["retrieved_at"], "retrieval_mode": r["mode"] or "live", "fallback_reason": r.get("fallback_reason")}
        if tool == "lookup_vulnerability":
            loc = c["locator"].lower()
            want = "NVD" if loc.startswith("nvd") or ("cvss" in loc and (r.get("cvss") or {}).get("locator", "").startswith("nvd")) else "CVE"
            ok = [s for s in r["sources"] if s["mode"]]
            src = next((s for s in ok if s["name"] == want), ok[0] if ok else r["sources"][0])
            prefix = "nvd" if src["name"] == "NVD" else "cve"
            dates = r.get("dates") or {}
            return {**base, "source_name": f"{'NIST NVD' if src['name'] == 'NVD' else 'CVE Program (cvelistV5)'} via lookup_vulnerability",
                    "source_type": "nvd" if src["name"] == "NVD" else "cve_record", "url_or_path": src["url"],
                    "published_date": _date(dates.get(f"{prefix}_published")), "last_modified_date": _date(dates.get(f"{prefix}_last_modified")),
                    "retrieved_at": src["retrieved_at"], "retrieval_mode": src["mode"], "fallback_reason": src.get("fallback_reason")}
        # tavily_search: attribute to the underlying page, not to the search engine
        results = r.get("results", [])
        m = re.search(r"results\[(\d+)\]", c["locator"])
        hit = results[int(m.group(1))] if m and int(m.group(1)) < len(results) else \
            next((x for x in results if x["url"] in c["locator"] or x["url"] in c["fact"]), results[0] if results else {})
        host = urlparse(hit.get("url", "")).netloc.lower()
        stype = "kb_article" if host.startswith("support.microsoft.com") else \
            "vendor_advisory" if host.endswith("microsoft.com") else "web_search"
        return {**base, "source_name": f"{host or 'web'} via tavily_search", "source_type": stype,
                "url_or_path": hit.get("url", ""), "published_date": _date(hit.get("published_date")),
                "retrieved_at": r["retrieved_at"], "retrieval_mode": "live"}


# ---------------------------------------------------------------- blocks

def _likelihood(lk: dict, facts: dict, ev: EvidenceBuilder, ts_ids: list[str], metrics: dict) -> dict:
    f = facts["likelihood"]
    reach, ea = f["reachability"], f["exploit_activity"]
    sc = lk["factors"]
    return {
        "aggregation": "sum",
        "factors": {
            "reachability": {"score": sc["reachability"]["score"], "max": 2, "defaulted": sc["reachability"]["defaulted"],
                             "basis": reach["basis"] if not sc["reachability"]["defaulted"]
                             else f"Reachability unknown; policy default of 1 applied. {reach['basis']}",
                             "evidence_ids": ev.ids(reach["citations"])},
            "exploitability": {"score": sc["exploitability"]["score"], "max": 2,
                               "cvss_av": metrics.get("AV"), "cvss_ac": metrics.get("AC"),
                               "cvss_pr": metrics.get("PR"), "cvss_ui": metrics.get("UI"),
                               "basis": f"AV:{metrics.get('AV')} AC:{metrics.get('AC')} PR:{metrics.get('PR')} UI:{metrics.get('UI')} "
                                        f"scores {sc['exploitability']['score']} ({EXPLOITABILITY_RULE}).",
                               "evidence_ids": ts_ids},
            "exploit_activity": {"score": sc["exploit_activity"]["score"], "max": 2,
                                 **{k: ea[k] for k in ("kev_listed", "credible_in_the_wild", "public_poc",
                                                       "vendor_exploitation_likely", "vendor_exploitability_assessment")},
                                 "basis": ea["basis"], "evidence_ids": ev.ids(ea["citations"])},
        },
        "raw_sum": lk["raw_sum"],
        "reachability_cap_applied": lk["reachability_cap_applied"],
        "final_score": lk["final_score"],
        "level": lk["level"],
    }


def _adj_note(a: dict, base: int) -> str:
    if a["input_status"] == "unknown":
        return "Input unknown; no adjustment made (policy)."
    if not a["triggered"]:
        return "Not triggered."
    if a["binding"]:
        return f"Triggered; changed impact by {a['effect']:+d}."
    return "Triggered but not binding: impact was already at the " + ("maximum." if a["effect"] > 0 else "minimum.")


def _impact(im: dict, facts: dict, ev: EvidenceBuilder) -> dict:
    f = facts["impact"]
    rto_ids = ev.ids(f["rto_hours"]["citations"])
    adjustments = []
    for a in im["adjustments"]:
        entry = {**a, "rule": ADJ_RULES[a["id"]], "note": _adj_note(a, im["base_score"])}
        if a["id"] == "ADJ-RTO" and rto_ids:
            entry["evidence_ids"] = rto_ids
        adjustments.append(entry)
    return {
        "aggregation": "max",
        "factors": {k: {"score": im["factors"][k]["score"], "max": 2, "basis": f[k]["basis"], "evidence_ids": ev.ids(f[k]["citations"])}
                    for k in ("asset_criticality", "blast_radius")},
        "base_score": im["base_score"],
        "adjustments": adjustments,
        "final_score": im["final_score"],
        "level": im["level"],
    }


def _tool_conflicts(trace: dict, ev: EvidenceBuilder) -> list[dict]:
    """Conflicts lookup_vulnerability detected between CVE and NVD."""
    out = []
    for cid, t in trace.items():
        if t["tool"] != "lookup_vulnerability" or t["result_status"] not in ("found", "not_found"):
            continue
        for i, text in enumerate(ev._result(cid).get("conflicts", [])):
            parts = [p.strip() for p in re.split(r":\s*|\s+vs\s+", text, maxsplit=2)[1:]]
            out.append({"fact": text, "values": parts if len(parts) >= 2 else [text, "see source records"],
                        "evidence_ids": ev.ids([{"call_id": cid, "locator": f"conflicts[{i}]", "fact": text}]),
                        "resolution": None})
    return out


# ---------------------------------------------------------------- assessment

def build_assessment(*, run: dict, intake: dict, settings: dict, facts: dict, policy_result: dict,
                     explanation: dict, trace: list[dict]) -> dict:
    ev = EvidenceBuilder(trace)
    d = policy_result["decision"]
    vuln_fixed = facts["threat"]["fix"].get("fixed_build")

    # Order evidence IDs by section so E1.. reads top to bottom.
    asset_ids = ev.ids(facts["asset"]["citations"])
    scope_ids = ev.ids(facts["scope_check"]["citations"])
    threat_ids = ev.ids(facts["threat"]["citations"])
    ts = facts["technical_severity"]
    ts_ids = ev.ids(ts["citations"])
    conditions = [{
        "id": c["id"],
        "description": CONDITION_TEXT[c["id"]].format(service=settings["inputs"]["vulnerable_service"],
                                                     fixed=f" ({vuln_fixed})" if vuln_fixed else ""),
        "result": c["result"], "basis": c["basis"], "evidence_ids": ev.ids(c["citations"]),
    } for c in sorted(facts["conditions"], key=lambda c: c["id"])]

    metrics = {}
    if ts.get("vector"):
        from policy import parse_cvss_vector
        metrics = parse_cvss_vector(ts["vector"])
    likelihood = _likelihood(policy_result["likelihood"], facts, ev, ts_ids, metrics) if policy_result["likelihood"] else None
    impact = _impact(policy_result["impact"], facts, ev) if policy_result["impact"] else None

    unknowns = [{"id": f"U{i}", **{k: u[k] for k in ("question", "decisive", "why_it_matters", "default_applied", "how_to_resolve")},
                 **({"condition_id": u["condition_id"]} if u.get("condition_id") else {})}
                for i, u in enumerate(facts["unknowns"], 1)]
    cond_result = {c["id"]: c["result"] for c in facts["conditions"]}
    missing = [u["id"] for u in unknowns if u["decisive"] and cond_result.get(u.get("condition_id")) == "unknown"]
    if not missing and d["policy_rule_applied"] == "P-IE":
        missing = [u["id"] for u in unknowns if u["decisive"]]

    conflicts = [{"id": None, "fact": x["fact"], "values": x["values"], "evidence_ids": ev.ids(x["citations"]),
                  "resolution": x["resolution"]} for x in facts["conflicts"]]
    conflicts += _tool_conflicts({t["call_id"]: t for t in trace}, ev)
    for i, x in enumerate(conflicts, 1):
        x["id"] = f"X{i}"

    prov = d["provisional"]
    decision = {
        "rating": d["rating"],
        "policy_rule_applied": d["policy_rule_applied"],
        "gate_reached": d["gate_reached"],
        "summary": explanation["decision_summary"],
        "missing_decisive_facts": missing,
        "provisional": None if not prov else {
            **prov, "condition": explanation.get("provisional_condition")
            or "Applies only if the missing decisive fact(s) resolve as vulnerable (all of C1-C3 true)."},
        "requires_analyst_review": True,
    }
    local_risk = f"{d['rating']} (provisional {prov['rating']}, {prov['policy_rule']})" if prov else \
        f"{d['rating']} ({d['policy_rule_applied']})"

    trace_out = [dict(t) for t in trace]
    by_call = {t["call_id"]: t for t in trace_out}
    for item in ev.items:
        by_call[item["tool_call_id"]]["evidence_ids"].append(item["evidence_id"])

    conf = policy_result["confidence"]
    assessment = {
        "assessment_id": run["run_id"],
        "generated_at": _now(),
        "run_metadata": {
            "agent_version": settings["agent_version"],
            "policy_version": policy_result["policy_version"],
            "prompt_version": run["prompt_version"],
            "model": {"provider": settings["model"]["provider"], "name": settings["model"]["name"],
                      "temperature": settings["model"]["temperature"], "max_tool_calls": settings["model"]["max_tool_calls"]},
            "threat_input": {**settings["inputs"]["threat_input"],
                             "role": "Saved case input (assignment requirement) and cached fallback for the CVE source. "
                                     "Not shown to the model; live CVE/NVD data comes from lookup_vulnerability (see tool_trace)."},
            "environment_snapshot": dict(settings["inputs"]["environment_snapshot"]),
            **{k: run[k] for k in ("run_id", "run_dir", "code_version", "transcript_path", "plan_rounds",
                                   "fabrication_rejections", "rejected_tool_requests", "budget_refused_calls",
                                   "completeness", "fact_validation",
                                   "explanation_status")},
        },
        "asset": {
            "asset_id": facts["asset"]["asset_id"],
            "environment_record": f"assets[asset_id={facts['asset']['asset_id']}]",
            **{k: facts["asset"][k] for k in ("asset_name", "services", "host_count", "sites", "tier", "operating_system",
                                               "os_build", "network_zone", "subnets")},
            "evidence_ids": asset_ids,
            "scope_check": {**{k: facts["scope_check"][k] for k in ("query", "result")}, "evidence_ids": scope_ids},
        },
        "threat": {
            "cve_id": facts["threat"]["cve_id"], "title": facts["threat"]["title"],
            "weakness_type": settings["inputs"]["weakness_type"],
            "affected_component": facts["threat"]["affected_component"],
            "affected_products_relevant": facts["threat"]["affected_products_relevant"],
            "fix": facts["threat"]["fix"], "evidence_ids": threat_ids,
        },
        "decision": decision,
        "severity_vs_local_risk": {
            "technical_severity": {**{k: ts[k] for k in ("cvss_version", "base_score", "base_severity", "vector", "source")},
                                   "evidence_ids": ts_ids},
            "local_risk": local_risk,
            "explanation": explanation["severity_vs_local_risk"],
        },
        "rationale": {
            "applicability": {"status": policy_result["applicability"]["status"],
                              "gate_1_outcome": policy_result["applicability"]["gate_1_outcome"], "conditions": conditions},
            "gate_2_status": policy_result["gate_2_status"],
            "likelihood": likelihood,
            "impact": impact,
            "matrix_result": policy_result["matrix_result"],
            "other_factors": facts["other_factors"],
        },
        "evidence": ev.items,
        "assumptions": [{"id": f"A{i}", **a} for i, a in enumerate(facts["assumptions"], 1)],
        "unknowns": unknowns,
        "confidence": {"level": conf["level"],
                       "explanation": f"{explanation['confidence_explanation']} Policy basis: {'; '.join(conf['reasons'])}."},
        "action": explanation["action"],
        "tool_trace": trace_out,
        "analyst_review": {"status": "pending", "reviewer": None, "reviewed_at": None, "citations_verified": None,
                           "agrees_with_rating": None, "group_consensus_rating": None, "notes": None},
    }
    if conflicts:
        assessment["conflicts"] = conflicts
    return assessment


def fallback_explanation(policy_result: dict, error: str) -> dict:
    """Used when the explanation step fails twice: code-written text, flagged for review."""
    d = policy_result["decision"]
    return {
        "decision_summary": f"{d['rating']} under {d['policy_rule_applied']}. The model explanation step failed ({error}); "
                            "this summary was written by code. Review the rationale and evidence directly.",
        "provisional_condition": None,
        "severity_vs_local_risk": "Explanation unavailable (model step failed). See technical_severity and rationale.",
        "confidence_explanation": f"Confidence {policy_result['confidence']['level']}.",
        "action": {"recommended_next_step": "Analyst to review this assessment manually; the explanation step failed.",
                   "priority": "High", "owner": "SOC analyst", "interim_measures": [],
                   "evidence_to_resolve": [{"evidence_needed": "Manual analyst review of rationale and evidence",
                                            "effect_on_decision": "Confirms or overrides the policy result"}]},
    }
