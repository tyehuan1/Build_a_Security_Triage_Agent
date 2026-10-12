"""Validate an assessment JSON.

1. Structure: JSON Schema (Resources/output_schema.json) - fields, types, allowed values.
2. Consistency: cross-field rules the schema does not express - evidence references,
   source labeling, tool-contract rules, and agreement with policy.py.

Usage:
    python validate.py assessment.json [--schema Resources/output_schema.json] [--write]

--write stores the check results in the assessment's "validation" block.
Exit code 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import jsonschema

from policy import PolicyInputs, evaluate, parse_cvss_vector

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "Resources" / "output_schema.json"

ENV_QUERY_TYPES = {"asset", "text", "flows", "business_service"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EVIDENCE_ID_RE = re.compile(r'"(E\d+)"')
DECISIVE_TOOLS = {"lookup_vulnerability", "environment_search"}
SUCCESS = ("found", "not_found")


def _check(results: list, name: str, problems: list[str]) -> None:
    results.append({"check": name, "passed": not problems, "detail": "; ".join(problems) or "ok"})


# ------------------------------------------------------------------ structure

def check_schema(a: dict, schema: dict) -> list[str]:
    v = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}" for e in v.iter_errors(a)]


# ------------------------------------------------------------------ references

def check_evidence_refs(a: dict) -> list[str]:
    ids = [e["evidence_id"] for e in a.get("evidence", [])]
    problems = [f"duplicate evidence_id {i}" for i in set(ids) if ids.count(i) > 1]
    body = json.dumps({k: v for k, v in a.items() if k not in ("evidence", "validation")})
    cited = set(EVIDENCE_ID_RE.findall(body))
    problems += [f"{i} cited but not in evidence[]" for i in sorted(cited - set(ids))]
    problems += [f"{i} in evidence[] but never cited" for i in sorted(set(ids) - cited)]
    return problems


def check_tool_refs(a: dict) -> list[str]:
    """Each evidence item must come from a successful call that lists it."""
    calls = {t["call_id"]: t for t in a.get("tool_trace", [])}
    problems = []
    for e in a.get("evidence", []):
        eid, cid = e["evidence_id"], e.get("tool_call_id")
        t = calls.get(cid)
        if t is None:
            problems.append(f"{eid} points to unknown tool call {cid}")
        elif t["result_status"] not in SUCCESS:
            problems.append(f"{eid} cites {cid}, which returned {t['result_status']}")
        elif eid not in t["evidence_ids"]:
            problems.append(f"{cid}.evidence_ids does not list {eid}")
    return problems


def check_unknown_refs(a: dict) -> list[str]:
    unknowns = {u["id"]: u for u in a.get("unknowns", [])}
    problems = []
    for uid in a["decision"].get("missing_decisive_facts") or []:
        if uid not in unknowns:
            problems.append(f"missing_decisive_facts lists {uid}, which is not in unknowns[]")
        elif not unknowns[uid]["decisive"]:
            problems.append(f"{uid} is listed as a missing decisive fact but unknowns[].decisive is false")
    if a["decision"]["policy_rule_applied"] == "P-IE" and not a["decision"].get("missing_decisive_facts"):
        problems.append("P-IE requires at least one entry in missing_decisive_facts")
    return problems


# ------------------------------------------------------------------ labeling

def check_labels(a: dict) -> list[str]:
    problems = []
    for e in a.get("evidence", []):
        if e["retrieval_mode"] == "cached" and not e.get("fallback_reason"):
            problems.append(f"{e['evidence_id']} is cached but has no fallback_reason")
        if e["source_type"] == "environment_snapshot" and e["retrieval_mode"] != "simulated":
            problems.append(f"{e['evidence_id']} comes from the environment but is not labeled simulated")
    return problems


# ------------------------------------------------------------------ tool contracts

def check_tool_contracts(a: dict) -> list[str]:
    problems = []
    invalid_counts: dict[str, int] = {}
    for t in a.get("tool_trace", []):
        cid, tool, args, status = t["call_id"], t["tool"], t["arguments"], t["result_status"]
        if status in ("failed", "invalid_request") and not t.get("error"):
            problems.append(f"{cid}: {status} without an error message")
        if status in ("invalid_request", "failed"):
            if status == "invalid_request":
                invalid_counts[tool] = invalid_counts.get(tool, 0) + 1
            if t["evidence_ids"]:
                problems.append(f"{cid}: a {status} call cannot produce evidence")
            continue
        if tool == "environment_search":
            if args.get("query_type") not in ENV_QUERY_TYPES:
                problems.append(f"{cid}: query_type must be one of {sorted(ENV_QUERY_TYPES)}")
            if not args.get("query"):
                problems.append(f"{cid}: environment_search requires a non-empty query")
            if t["mode"] not in ("simulated", None):
                problems.append(f"{cid}: environment_search mode must be simulated")
        elif tool == "tavily_search":
            for k in ("query", "allowed_domains", "max_results"):
                if k not in args:
                    problems.append(f"{cid}: tavily_search missing argument {k}")
            if t["mode"] not in ("live", None) or t["fallback_used"]:
                problems.append(f"{cid}: tavily_search is live only with no fallback")
        elif tool in ("lookup_kev", "lookup_vulnerability"):
            if not CVE_RE.match(str(args.get("cve_id", ""))):
                problems.append(f"{cid}: invalid cve_id {args.get('cve_id')!r}")
    for tool, n in invalid_counts.items():
        if n > 1:
            problems.append(f"{tool}: {n} invalid requests; only one correction attempt is allowed")
    return problems


def check_raw_outputs(a: dict) -> list[str]:
    """Each saved raw tool output still exists, matches its SHA-256, and belongs to its trace entry."""
    problems = []
    for t in a.get("tool_trace", []):
        rel = t.get("raw_output_path")
        if not rel:
            continue
        p = Path(rel) if Path(rel).is_absolute() else ROOT / rel
        if not p.is_file():
            problems.append(f"{t['call_id']}: raw output {rel} not found")
            continue
        data = p.read_bytes()
        if t.get("output_sha256") and hashlib.sha256(data).hexdigest() != t["output_sha256"]:
            problems.append(f"{t['call_id']}: raw output SHA-256 does not match the trace")
        raw = json.loads(data.decode("utf-8"))
        for k_raw, k_trace in (("call_id", "call_id"), ("tool", "tool"), ("arguments", "arguments"), ("status", "result_status")):
            if raw.get(k_raw) != t.get(k_trace):
                problems.append(f"{t['call_id']}: raw output {k_raw} {raw.get(k_raw)!r} != trace {t.get(k_trace)!r}")
    return problems


def check_kev_matches_tool(a: dict) -> list[str]:
    lk = a["rationale"].get("likelihood")
    if not lk:
        return []
    recorded = lk["factors"]["exploit_activity"]["kev_listed"]
    kev_calls = [t for t in a["tool_trace"] if t["tool"] == "lookup_kev" and t["result_status"] in SUCCESS]
    if not kev_calls:
        return [] if recorded is None else ["kev_listed is set but no successful lookup_kev call exists"]
    expected = kev_calls[-1]["result_status"] == "found"
    return [] if recorded == expected else [f"kev_listed is {recorded} but lookup_kev returned {kev_calls[-1]['result_status']}"]


def check_conflicts(a: dict) -> list[str]:
    if a["decision"]["policy_rule_applied"] == "P-RV-C" and not a.get("conflicts"):
        return ["P-RV-C requires at least one entry in conflicts[]"]
    return []


def check_cvss_consistency(a: dict) -> list[str]:
    lk = a["rationale"].get("likelihood")
    vector = a["severity_vs_local_risk"]["technical_severity"].get("vector")
    if not lk or not vector:
        return []
    m = parse_cvss_vector(vector)
    ex = lk["factors"]["exploitability"]
    return [f"exploitability.cvss_{k.lower()} is {ex.get('cvss_' + k.lower())} but vector has {m.get(k)}"
            for k in ("AV", "AC", "PR", "UI") if ex.get("cvss_" + k.lower()) != m.get(k)]


# ------------------------------------------------------------------ policy

def inputs_from_assessment(a: dict) -> PolicyInputs:
    """Rebuild the policy inputs from what the assessment recorded."""
    r = a["rationale"]
    trace = a["tool_trace"]
    vector = a["severity_vs_local_risk"]["technical_severity"].get("vector")
    # A decisive tool counts as failed when no call to it succeeded (all failed, or never run).
    completed = {t["tool"] for t in trace if t["result_status"] in SUCCESS}
    kw = dict(
        conditions={c["id"]: c["result"] for c in r["applicability"]["conditions"]},
        decisive_tool_failure=not DECISIVE_TOOLS <= completed,
        any_tool_failed=any(t["result_status"] == "failed" for t in trace),
        assumptions_used=bool(a.get("assumptions")),
        cvss_metrics=parse_cvss_vector(vector) if vector else None,
    )
    if r.get("likelihood"):
        f = r["likelihood"]["factors"]
        reach = f["reachability"]
        ea = f["exploit_activity"]
        kw.update(
            reachability=None if reach["defaulted"] else reach["score"],
            kev_listed=ea["kev_listed"],
            credible_in_the_wild=ea["credible_in_the_wild"],
            public_poc=ea["public_poc"],
            vendor_exploitation_likely=ea["vendor_exploitation_likely"],
        )
    if r.get("impact"):
        f = r["impact"]["factors"]
        rto = next((x for x in r["impact"]["adjustments"] if x["id"] == "ADJ-RTO"), None)
        kw.update(
            asset_criticality=f["asset_criticality"]["score"],
            blast_radius=f["blast_radius"]["score"],
            rto_hours=rto["input_value"] if rto and rto["input_status"] == "known" else None,
        )
    return PolicyInputs(**kw)


def _diff(path: str, expected, actual, out: list[str]) -> None:
    if expected != actual:
        out.append(f"{path}: policy gives {expected!r}, assessment has {actual!r}")


def check_policy(a: dict) -> list[str]:
    try:
        exp = evaluate(inputs_from_assessment(a))
    except (ValueError, KeyError, TypeError) as err:
        return [f"policy could not be applied: {err}"]
    r, d, out = a["rationale"], a["decision"], []

    for k in ("rating", "policy_rule_applied", "gate_reached"):
        _diff(f"decision.{k}", exp["decision"][k], d[k], out)
    prov = d.get("provisional")
    _diff("decision.provisional", exp["decision"]["provisional"],
          {k: prov[k] for k in ("rating", "policy_rule", "binding")} if prov else None, out)
    for k in ("status", "gate_1_outcome"):
        _diff(f"applicability.{k}", exp["applicability"][k], r["applicability"][k], out)
    _diff("gate_2_status", exp["gate_2_status"], r["gate_2_status"], out)
    _diff("confidence.level", exp["confidence"]["level"], a["confidence"]["level"], out)

    for block in ("likelihood", "impact", "matrix_result"):
        e, got = exp[block], r.get(block)
        if (e is None) != (got is None):
            out.append(f"{block}: policy gives {'null' if e is None else 'a value'}, assessment has {'null' if got is None else 'a value'}")
            continue
        if e is None:
            continue
        if block == "matrix_result":
            for k, v in e.items():
                _diff(f"matrix_result.{k}", v, got[k], out)
            continue
        for fname, fexp in e["factors"].items():
            for k, v in fexp.items():
                _diff(f"{block}.factors.{fname}.{k}", v, got["factors"][fname][k], out)
        for k in e:
            if k not in ("factors", "adjustments"):
                _diff(f"{block}.{k}", e[k], got[k], out)
        if block == "impact":
            got_adj = {x["id"]: x for x in got["adjustments"]}
            for adj in e["adjustments"]:
                g = got_adj.get(adj["id"])
                if not g:
                    out.append(f"impact.adjustments: {adj['id']} missing")
                    continue
                for k in ("triggered", "effect", "binding", "input_status"):
                    _diff(f"impact.adjustments[{adj['id']}].{k}", adj[k], g[k], out)
    return out


# ------------------------------------------------------------------ entry point

def validate_assessment(a: dict, schema: dict) -> dict:
    results: list = []
    schema_problems = check_schema(a, schema)
    _check(results, "Output matches output_schema.json", schema_problems)
    if schema_problems:  # later checks assume a well-formed document
        return {"schema_valid": False, "checks": results}
    _check(results, "Every cited evidence_id exists and every evidence item is cited", check_evidence_refs(a))
    _check(results, "Every evidence item comes from a successful call in tool_trace", check_tool_refs(a))
    _check(results, "Missing decisive facts are listed in unknowns[]", check_unknown_refs(a))
    _check(results, "Cached evidence has a fallback reason; environment evidence is labeled simulated", check_labels(a))
    _check(results, "Tool calls follow the tool contracts", check_tool_contracts(a))
    _check(results, "Raw tool outputs exist, match their SHA-256 and their trace entry", check_raw_outputs(a))
    _check(results, "kev_listed matches the lookup_kev result", check_kev_matches_tool(a))
    _check(results, "Exploitability CVSS fields match the CVSS vector", check_cvss_consistency(a))
    _check(results, "Review Needed for conflicting evidence lists the conflicts", check_conflicts(a))
    _check(results, "Decision, scores, matrix and confidence match policy.py", check_policy(a))
    return {"schema_valid": True, "checks": results}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("assessment", type=Path)
    ap.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    ap.add_argument("--write", action="store_true", help="store results in the assessment's validation block")
    args = ap.parse_args()

    a = json.loads(args.assessment.read_text(encoding="utf-8"))
    report = validate_assessment(a, json.loads(args.schema.read_text(encoding="utf-8")))
    for c in report["checks"]:
        print(f"[{'PASS' if c['passed'] else 'FAIL'}] {c['check']}" + ("" if c["passed"] else f"\n       {c['detail']}"))
    if args.write:
        a["validation"] = report
        args.assessment.write_text(json.dumps(a, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if all(c["passed"] for c in report["checks"]) else 1


if __name__ == "__main__":
    sys.exit(main())
