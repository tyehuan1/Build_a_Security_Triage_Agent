"""Prompts and model-output schemas for the three model steps in the design's workflow table.

  1. Plan tool calling / follow-up loop  -> PLAN_SYSTEM, plan_user()
  2. Extract facts and assign scores      -> EXTRACT_SYSTEM, extract_user(), EXTRACTION_SCHEMA
  3. Explain and recommend                -> EXPLAIN_SYSTEM, explain_user(), EXPLANATION_SCHEMA

Plus the corrective messages the orchestrator sends inside the loops (fabricated tool output,
missing required evidence, round cap, failed fact validation).

The model never computes likelihood/impact totals, the matrix result, the rating, the policy rule or
the confidence level; policy.py does. Every run saves prompt_bundle() to <run folder>/other_info/prompts.json.
"""

from __future__ import annotations

import json

PROMPT_VERSION = "prompts-v1.1"  # v1.1: scope_check defined (first live run answered the wrong question)
COMPLETE_SIGNAL = "EVIDENCE GATHERING COMPLETE"

# ---------------------------------------------------------------------------------------------
# Shared policy text (from Project_Design.docx, "Rating Policy"). Used by the extraction prompt so
# the model scores the judgment factors with the group's exact definitions.
# ---------------------------------------------------------------------------------------------

APPLICABILITY_CONDITIONS = """\
C1: The asset's OS is in the CVE's affected products list.
C2: The DNS Server service (the vulnerable component) is installed on the asset.
C3: The asset's OS build is below the fixed build that lookup_vulnerability reports for that OS."""

CONDITION_RESULTS = """\
"true"        - the tool evidence shows the condition holds.
"false"       - the tool evidence explicitly shows it does not hold (e.g. a build at or above the fixed build).
"unknown"     - the evidence needed to decide is missing (e.g. os_build is null). null means unknown, never safe.
"conflicting" - two cited sources disagree on a fact this condition depends on."""

FACTOR_RUBRIC = """\
Reachability (vulnerable service on the asset, from the attacker's side):
  0 = isolated (no realistic network path)   1 = broad internal access   2 = public-facing / Internet-exposed
  Use null only if the evidence cannot support any score; policy then defaults to 1.
Exploit activity inputs (booleans; null = not determined):
  kev_listed                 - from lookup_kev in_kev.
  credible_in_the_wild       - a vendor, government or known security-vendor report of exploitation in the wild (outside KEV).
  public_poc                 - a credible public proof-of-concept exists.
  vendor_exploitation_likely - the vendor rates exploitation as likely (e.g. Microsoft "Exploitation More Likely").
Asset criticality: 0 = non-critical   1 = business-important   2 = critical
Blast radius:      0 = single host    1 = entire service or department   2 = domain / organization-wide
RTO: the recovery time objective in hours of the business service the asset supports (null if not stated)."""

# ---------------------------------------------------------------------------------------------
# 1. Plan tool calling and follow-up loop
# ---------------------------------------------------------------------------------------------

PLAN_SYSTEM = f"""\
You are the evidence-gathering stage of a security triage agent for Northbridge Services' SOC.
Your job is to collect the evidence needed to rate the local risk of one vulnerability to one asset.
You do not assign the rating; later stages score the evidence with the group's policy.

How to work:
- Gather evidence ONLY by calling the provided tools through the tool-calling interface.
- Never write a tool call, tool arguments or a tool result as text. Never invent or predict tool output.
  Text that imitates a tool call or result is rejected and wastes a round.
- Do not answer from memory. A fact counts only if a tool returned it in this conversation.
- Every tool result carries a call_id (T1, T2, ...) assigned by the system. Refer to results by that ID.
- In the environment snapshot, null means unknown. Never treat null as safe or as a negative.
- If a tool returns an error for invalid arguments, read the error and correct the call once.
- You may request several tools in one turn. You have at most {{max_rounds}} tool-calling rounds.

Evidence the later stages need (you decide which tools and queries cover each item):
1. The vulnerability: affected products, the fixed build for the asset's OS, CVSS vector and score.
2. The asset record: OS, OS build / installed KBs, services, zone, tier, host count.
3. Scope: whether any other asset runs the vulnerable service.
4. Reachability: network paths to the asset, perimeter policy, and whether the service is published to the Internet.
5. Business impact: the business service(s) the asset supports, their consequence of loss, RTO and RPO.
6. Known exploitation: CISA KEV status.
7. Exploit activity and remediation context from credible web sources: the vendor's exploitability
   assessment, any in-the-wild exploitation or public proof-of-concept reports, and the patch/KB.

When every item is covered, or the tools cannot provide more, reply with no tool calls and with text
that starts with "{COMPLETE_SIGNAL}", followed by one line per item above naming the call_id(s) that
cover it, or "not available" and why."""


def plan_system(max_rounds: int) -> str:
    return PLAN_SYSTEM.replace("{max_rounds}", str(max_rounds))


def plan_user(intake: dict) -> str:
    return f"""\
Risk question: {intake['risk_question']}

Assessment inputs (validated at intake):
- Threat: {intake['cve_id']} (saved input: {intake['threat_input_path']})
- Asset: {intake['asset_id']}
- Environment snapshot: {intake['environment_id']} ({intake['environment_data_type']}; {intake['environment_path']})
- Assessment date: {intake['run_date']}

Begin gathering evidence."""


FABRICATION_REJECTED = """\
Your last reply was rejected: it contains text that looks like a tool call or tool result ({reasons}).
Tool output is only real when the system returns it to you with a call_id. Request tools through the
tool-calling interface, or reply with "{complete}" if evidence gathering is finished."""

ROUND_CAP_REACHED = f"""\
The tool-calling round limit has been reached. Do not request more tools. Reply now with
"{COMPLETE_SIGNAL}" and the per-item call_id summary, marking anything not covered as "not available"."""

MISSING_REQUIRED_EVIDENCE = """\
Evidence gathering cannot finish yet. These required lookups have not succeeded: {missing}.
Call them now through the tool-calling interface (one attempt), then reply with "{complete}"."""


# ---------------------------------------------------------------------------------------------
# 2. Extract facts and assign scores
# ---------------------------------------------------------------------------------------------

EXTRACT_SYSTEM = f"""\
You are the fact-extraction stage of a security triage agent. You receive the results of the tool
calls made in this run. Turn them into the structured facts that the group's rating policy needs.
Code will check your facts against the saved tool outputs and compute the rating; you do not rate.

Citation rules (strict):
- Every fact you state must cite at least one tool result as {{"call_id", "locator", "fact"}}.
  Only a null / "unknown" value may have an empty citations list.
- call_id must be one of the call IDs listed in the tool results below. Never invent a call ID.
- locator must point inside that result: a record locator from environment_search
  (e.g. "assets[asset_id=W01]", "flows[flow_id=F09]") or a field path in the result
  (e.g. "cvss.vector", "affected[product='Windows Server 2022'].fixed_build", "in_kev", "results[0].snippet").
- "fact" is one sentence stating what that source says.
- Copy identifiers exactly as the tool returned them: CVSS vector strings, builds, KB numbers, asset IDs, RTO hours.
- A value the tools did not return is unknown: use null and list it in unknowns. Never fill gaps from memory.

Applicability conditions:
{APPLICABILITY_CONDITIONS}

Condition results:
{CONDITION_RESULTS}

Scoring definitions for the judgment factors:
{FACTOR_RUBRIC}

Also record:
- scope_check: whether any asset OTHER than the assessed asset runs the vulnerable service. Use the
  environment_search coverage block (matching_asset_ids out of assets_searched, and the completeness
  statement) and cite it with locator "coverage". query = that question; result = the answer.
- assumptions: anything you had to assume that affects a condition or a score (say which, e.g. "likelihood.reachability").
- unknowns: open questions. Set decisive=true only if the answer would change a condition (C1-C3);
  give condition_id for decisive unknowns.
- conflicts: only when two cited sources give different values for the same fact.
- The technical severity (CVSS) describes the flaw in general; local risk depends on this environment.
  Report the CVSS exactly as returned; do not adjust it.

Return only the JSON object described by the schema."""


def extract_user(intake: dict, tool_results: list[dict]) -> str:
    """tool_results: the payloads returned to the model, successful calls only (call_id, tool, arguments, result)."""
    return f"""\
Assessment: {intake['cve_id']} on asset {intake['asset_id']} ({intake['environment_id']}).

Tool results from this run ({len(tool_results)} successful calls):
{json.dumps(tool_results, indent=1, ensure_ascii=False)}

Extract the facts now."""


FACT_VALIDATION_FAILED = """\
Code validation rejected your extraction. Fix every problem below and return the complete corrected
JSON object (not just the changed parts). This is the only retry.

Problems:
{problems}"""


# Empty citations are allowed only for null/unknown values; factcheck.py requires citations for every asserted fact.
_CITATIONS = {"type": "array", "items": {
    "type": "object", "required": ["call_id", "locator", "fact"], "additionalProperties": False,
    "properties": {"call_id": {"type": "string", "pattern": r"^T\d+$"}, "locator": {"type": "string", "minLength": 1},
                   "fact": {"type": "string", "minLength": 1}}}}
_SCORE = {"type": ["integer", "null"], "minimum": 0, "maximum": 2}
_BOOL = {"type": ["boolean", "null"]}


def _scored(value_schema: dict) -> dict:
    return {"type": "object", "required": ["value", "basis", "citations"], "additionalProperties": False,
            "properties": {"value": value_schema, "basis": {"type": "string", "minLength": 1}, "citations": _CITATIONS}}


EXTRACTION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["asset", "scope_check", "threat", "technical_severity", "conditions", "likelihood", "impact",
                 "assumptions", "unknowns", "conflicts", "other_factors"],
    "properties": {
        "asset": {
            "type": "object", "additionalProperties": False,
            "required": ["asset_id", "asset_name", "services", "host_count", "sites", "tier", "operating_system",
                         "os_build", "network_zone", "subnets", "citations"],
            "properties": {
                "asset_id": {"type": "string"}, "asset_name": {"type": "string"},
                "services": {"type": "array", "items": {"type": "string"}},
                "host_count": {"type": ["integer", "null"]},
                "sites": {"type": ["object", "null"], "additionalProperties": {"type": "integer"}},
                "tier": {"type": ["string", "null"]}, "operating_system": {"type": ["string", "null"]},
                "os_build": {"type": ["string", "null"]}, "network_zone": {"type": ["string", "null"]},
                "subnets": {"type": "array", "items": {"type": "string"}}, "citations": _CITATIONS}},
        "scope_check": {
            "type": "object", "additionalProperties": False, "required": ["query", "result", "citations"],
            "properties": {"query": {"type": "string"}, "result": {"type": "string"}, "citations": _CITATIONS}},
        "threat": {
            "type": "object", "additionalProperties": False,
            "required": ["cve_id", "title", "affected_component", "affected_products_relevant", "fix", "citations"],
            "properties": {
                "cve_id": {"type": "string"}, "title": {"type": "string"}, "affected_component": {"type": "string"},
                "affected_products_relevant": {"type": "array", "items": {"type": "string"}},
                "fix": {"type": "object", "additionalProperties": False, "required": ["kb", "fixed_build"],
                        "properties": {"kb": {"type": ["string", "null"]}, "fixed_build": {"type": ["string", "null"]}}},
                "citations": _CITATIONS}},
        "technical_severity": {
            "type": "object", "additionalProperties": False,
            "required": ["cvss_version", "base_score", "base_severity", "vector", "source", "citations"],
            "properties": {
                "cvss_version": {"type": ["string", "null"]}, "base_score": {"type": ["number", "null"]},
                "base_severity": {"enum": ["None", "Low", "Medium", "High", "Critical", None]},
                "vector": {"type": ["string", "null"]}, "source": {"type": ["string", "null"]}, "citations": _CITATIONS}},
        "conditions": {
            "type": "array", "minItems": 3, "maxItems": 3,
            "items": {"type": "object", "additionalProperties": False, "required": ["id", "result", "basis", "citations"],
                      "properties": {"id": {"enum": ["C1", "C2", "C3"]},
                                     "result": {"enum": ["true", "false", "unknown", "conflicting"]},
                                     "basis": {"type": "string", "minLength": 1}, "citations": _CITATIONS}}},
        "likelihood": {
            "type": "object", "additionalProperties": False, "required": ["reachability", "exploit_activity"],
            "properties": {
                "reachability": _scored(_SCORE),
                "exploit_activity": {
                    "type": "object", "additionalProperties": False,
                    "required": ["kev_listed", "credible_in_the_wild", "public_poc", "vendor_exploitation_likely",
                                 "vendor_exploitability_assessment", "basis", "citations"],
                    "properties": {"kev_listed": _BOOL, "credible_in_the_wild": _BOOL, "public_poc": _BOOL,
                                   "vendor_exploitation_likely": _BOOL,
                                   "vendor_exploitability_assessment": {"type": ["string", "null"]},
                                   "basis": {"type": "string", "minLength": 1}, "citations": _CITATIONS}}}},
        "impact": {
            "type": "object", "additionalProperties": False, "required": ["asset_criticality", "blast_radius", "rto_hours"],
            "properties": {"asset_criticality": _scored(_SCORE), "blast_radius": _scored(_SCORE),
                           "rto_hours": _scored({"type": ["number", "null"], "minimum": 0})}},
        "assumptions": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["statement", "reason", "affects"],
            "properties": {"statement": {"type": "string"}, "reason": {"type": "string"},
                           "affects": {"type": "array", "items": {"type": "string"}}}}},
        "unknowns": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["question", "decisive", "condition_id", "why_it_matters", "default_applied", "how_to_resolve"],
            "properties": {"question": {"type": "string"}, "decisive": {"type": "boolean"},
                           "condition_id": {"enum": ["C1", "C2", "C3", None]}, "why_it_matters": {"type": "string"},
                           "default_applied": {"type": "string"}, "how_to_resolve": {"type": "string"}}}},
        "conflicts": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["fact", "values", "citations", "resolution"],
            "properties": {"fact": {"type": "string"}, "values": {"type": "array", "items": {"type": "string"}, "minItems": 2},
                           "citations": _CITATIONS, "resolution": {"type": ["string", "null"]}}}},
        "other_factors": {"type": "array", "items": {"type": "string"}},
    },
}


# ---------------------------------------------------------------------------------------------
# 3. Explain and recommend
# ---------------------------------------------------------------------------------------------

EXPLAIN_SYSTEM = """\
You are the explanation stage of a security triage agent. The rating has already been computed by
code from validated facts using the group's policy. Explain it to a SOC analyst and recommend action.

Rules:
- Do not change, re-score or second-guess the decision, policy rule, scores or confidence level.
  Explain them as given. Any scores you write are ignored.
- Use only the validated facts provided. Do not add facts from memory.
- Separate technical severity (CVSS: how bad the flaw is in general) from local risk (this asset in
  this environment). Say why they differ, if they do.
- If the decision is Insufficient Evidence, say clearly that the rating is not binding, name the
  missing decisive fact(s), and state the provisional rating and the condition under which it applies.
- If the decision is Review Needed, say what failed or conflicted and what a human must check.
- The recommended next step must be concrete and doable (who checks what, and how).
- evidence_to_resolve: list the specific findings that would resolve or change the decision and the
  effect each would have under the policy (e.g. "C3 = false -> Low (P-NA)").
- The confidence explanation must justify the given confidence level using the given reasons.
- Plain, precise language. No marketing tone.

Return only the JSON object described by the schema."""


def explain_user(intake: dict, decision: dict, facts: dict) -> str:
    return f"""\
Assessment: {intake['cve_id']} on asset {intake['asset_id']}.

Decision computed by policy.py (do not change):
{json.dumps(decision, indent=1, ensure_ascii=False)}

Validated facts:
{json.dumps(facts, indent=1, ensure_ascii=False)}

Write the explanation and recommendation now."""


EXPLANATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["decision_summary", "severity_vs_local_risk", "confidence_explanation", "action"],
    "properties": {
        "decision_summary": {"type": "string", "minLength": 1},
        "provisional_condition": {"type": ["string", "null"]},
        "severity_vs_local_risk": {"type": "string", "minLength": 1},
        "confidence_explanation": {"type": "string", "minLength": 1},
        "action": {
            "type": "object", "additionalProperties": False,
            "required": ["recommended_next_step", "priority", "owner", "interim_measures", "evidence_to_resolve"],
            "properties": {
                "recommended_next_step": {"type": "string", "minLength": 1},
                "priority": {"enum": ["Immediate", "High", "Normal", "Low"]},
                "owner": {"type": "string"},
                "interim_measures": {"type": "array", "items": {"type": "string"}},
                "evidence_to_resolve": {"type": "array", "minItems": 1, "items": {
                    "type": "object", "additionalProperties": False, "required": ["evidence_needed", "effect_on_decision"],
                    "properties": {"evidence_needed": {"type": "string"}, "effect_on_decision": {"type": "string"}}}},
            }},
    },
}


# ---------------------------------------------------------------------------------------------
# Run record
# ---------------------------------------------------------------------------------------------

def prompt_bundle(max_rounds: int) -> dict:
    """Every prompt and schema exactly as used, saved with each run."""
    return {
        "prompt_version": PROMPT_VERSION,
        "plan_system": plan_system(max_rounds),
        "plan_user_template": plan_user({k: f"<{k}>" for k in ("risk_question", "cve_id", "threat_input_path", "asset_id",
                                                                 "environment_id", "environment_data_type",
                                                                 "environment_path", "run_date")}),
        "fabrication_rejected": FABRICATION_REJECTED,
        "round_cap_reached": ROUND_CAP_REACHED,
        "missing_required_evidence": MISSING_REQUIRED_EVIDENCE,
        "extract_system": EXTRACT_SYSTEM,
        "extraction_schema": EXTRACTION_SCHEMA,
        "fact_validation_failed": FACT_VALIDATION_FAILED,
        "explain_system": EXPLAIN_SYSTEM,
        "explanation_schema": EXPLANATION_SCHEMA,
    }
