"""Northbridge rating policy (rating-policy-v1.0).

Deterministic implementation of the group's applicability-and-impact policy.
The model gathers facts with tools and records its judgments (condition
results, reachability, criticality, blast radius). This module turns those
facts into scores, a rating and a policy rule. The model never picks the
rating itself.

Gate 1 - Applicability (C1 affected OS, C2 DNS Server installed, C3 build
below fixed build). Precedence when several outcomes are possible:
    0. fact validation failed twice -> P-RV-F (the facts cannot be trusted at all)
    1. any condition "false"       -> P-NA  (Low, Not Applicable)
    2. decisive tool failure       -> P-RV-F (Review Needed)
    3. any condition "conflicting" -> P-RV-C (Review Needed)
    4. any condition "unknown"     -> P-IE  (Insufficient Evidence)
    5. all "true"                  -> Gate 2
A confirmed "false" wins because one missing prerequisite is enough to show
the vulnerability is not present. This order follows the "Applicability
gate 1" row of the design's workflow table.

Gate 2 - Likelihood (sum, 0-6) x Impact (max, 0-2) -> rating matrix.
When Gate 1 ends in P-IE and Gate 2 inputs are available, Gate 2 is also
computed as a non-binding provisional rating for prioritization.

Confidence (design, "Evidence and Uncertainty"):
    Low    - a decisive fact is unknown or a required lookup failed (P-IE, P-RV-C, P-RV-F)
    Medium - an assumption fed applicability or scoring, reachability was
             defaulted, or any tool call failed
    High   - every factor is cited to a source
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

POLICY_VERSION = "rating-policy-v1.0"

CONDITION_VALUES = {"true", "false", "unknown", "conflicting"}
REQUIRED_CONDITIONS = {"C1", "C2", "C3"}
LEVEL_CODE = {"Low": "L", "Medium": "M", "High": "H"}
IMPACT_LEVELS = ["Low", "Medium", "High"]

# Rows: likelihood level, columns: impact level.
MATRIX = {
    "Low": {"Low": "Low", "Medium": "Low", "High": "Medium"},
    "Medium": {"Low": "Low", "Medium": "Medium", "High": "High"},
    "High": {"Low": "Medium", "Medium": "High", "High": "High"},
}


@dataclass
class PolicyInputs:
    """Facts the agent gathered. None means unknown."""

    conditions: dict[str, str]                  # {"C1": "true", "C2": "true", "C3": "unknown"}
    decisive_tool_failure: bool = False         # lookup_vulnerability or environment_search failed, no cache
    fact_validation_failed: bool = False        # extracted facts failed code validation twice (workflow table)

    # Confidence
    any_tool_failed: bool = False               # any tool call ended in status=failed
    assumptions_used: bool = False              # an assumption fed applicability or scoring

    # Likelihood
    reachability: Optional[int] = None          # 0 isolated, 1 broad internal, 2 Internet-facing; None -> default 1
    cvss_metrics: Optional[dict[str, str]] = None  # {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "H", "I": "H", "A": "H"}
    kev_listed: Optional[bool] = None
    credible_in_the_wild: Optional[bool] = None
    public_poc: Optional[bool] = None
    vendor_exploitation_likely: Optional[bool] = None

    # Impact
    asset_criticality: Optional[int] = None     # 0 non-critical, 1 business-important, 2 critical
    blast_radius: Optional[int] = None          # 0 single host, 1 service/department, 2 domain/organization
    rto_hours: Optional[float] = None

    def __post_init__(self) -> None:
        missing = REQUIRED_CONDITIONS - set(self.conditions)
        if missing:
            raise ValueError(f"conditions must include {sorted(REQUIRED_CONDITIONS)}; missing {sorted(missing)}")
        for cid, val in self.conditions.items():
            if val not in CONDITION_VALUES:
                raise ValueError(f"{cid}: '{val}' is not one of {sorted(CONDITION_VALUES)}")
        for name in ("reachability", "asset_criticality", "blast_radius"):
            val = getattr(self, name)
            if val is not None and val not in (0, 1, 2):
                raise ValueError(f"{name} must be 0, 1, 2 or None, got {val!r}")


# ---------------------------------------------------------------- Gate 1

def gate_1(inp: PolicyInputs) -> tuple[str, str]:
    """Return (applicability_status, gate_1_outcome)."""
    values = set(inp.conditions.values())
    if inp.fact_validation_failed:
        return "Unknown", "P-RV-F"
    if "false" in values:
        return "Not Applicable", "P-NA"
    if inp.decisive_tool_failure:
        return "Unknown", "P-RV-F"
    if "conflicting" in values:
        return "Conflicting", "P-RV-C"
    if "unknown" in values:
        return "Unknown", "P-IE"
    return "Confirmed", "Gate 2"


# ---------------------------------------------------------------- Gate 2

def exploitability_score(m: dict[str, str]) -> int:
    if m.get("AV") in ("L", "P"):
        return 0
    if m.get("AV") in ("N", "A") and m.get("AC") == "L" and m.get("PR") == "N" and m.get("UI") == "N":
        return 2
    if m.get("AV") in ("N", "A"):
        return 1
    raise ValueError(f"Cannot score exploitability from CVSS metrics {m}")


def exploit_activity_score(inp: PolicyInputs) -> int:
    if inp.kev_listed or inp.credible_in_the_wild:
        return 2
    if inp.public_poc or inp.vendor_exploitation_likely:
        return 1
    return 0


def likelihood_level(score: int) -> str:
    return "Low" if score <= 2 else "Medium" if score <= 4 else "High"


def gate_2_available(inp: PolicyInputs) -> bool:
    return inp.cvss_metrics is not None and inp.asset_criticality is not None and inp.blast_radius is not None


def likelihood(inp: PolicyInputs) -> dict:
    defaulted = inp.reachability is None
    reach = 1 if defaulted else inp.reachability
    expl = exploitability_score(inp.cvss_metrics)
    act = exploit_activity_score(inp)
    raw = reach + expl + act
    cap = reach == 0
    final = min(raw, 1) if cap else raw
    return {
        "factors": {
            "reachability": {"score": reach, "defaulted": defaulted},
            "exploitability": {"score": expl},
            "exploit_activity": {"score": act},
        },
        "raw_sum": raw,
        "reachability_cap_applied": cap,
        "final_score": final,
        "level": likelihood_level(final),
    }


def _clamp(x: int) -> int:
    return max(0, min(2, x))


def impact(inp: PolicyInputs) -> dict:
    base = max(inp.asset_criticality, inp.blast_radius)
    m = inp.cvss_metrics

    rto_known = inp.rto_hours is not None
    rto_trig = rto_known and inp.rto_hours <= 4
    cia_trig = all(m.get(k) in ("L", "N") for k in ("C", "I", "A"))
    effects = {"ADJ-RTO": 1 if rto_trig else 0, "ADJ-CIA": -1 if cia_trig else 0}

    final = _clamp(base + sum(effects.values()))
    adjustments = []
    for adj_id, triggered, status, value in (
        ("ADJ-RTO", rto_trig, "known" if rto_known else "unknown", inp.rto_hours),
        ("ADJ-CIA", cia_trig, "known", f"C:{m.get('C')}/I:{m.get('I')}/A:{m.get('A')}"),
    ):
        without = _clamp(base + sum(v for k, v in effects.items() if k != adj_id))
        adjustments.append({
            "id": adj_id,
            "input_value": value,
            "input_status": status,
            "triggered": triggered,
            "effect": effects[adj_id],
            "binding": without != final,
        })
    return {
        "factors": {
            "asset_criticality": {"score": inp.asset_criticality},
            "blast_radius": {"score": inp.blast_radius},
        },
        "base_score": base,
        "adjustments": adjustments,
        "final_score": final,
        "level": IMPACT_LEVELS[final],
    }


def matrix(lk: dict, im: dict) -> dict:
    rating = MATRIX[lk["level"]][im["level"]]
    return {
        "likelihood_level": lk["level"],
        "impact_level": im["level"],
        "rating": rating,
        "policy_rule": f"P-{LEVEL_CODE[rating]}-L{lk['final_score']}I{im['final_score']}",
    }


# ---------------------------------------------------------------- Confidence

def confidence(inp: PolicyInputs, outcome: str, lk: Optional[dict]) -> dict:
    reasons = []
    if outcome == "P-IE":
        reasons.append("a decisive applicability fact is unknown")
    elif outcome == "P-RV-C":
        reasons.append("sources conflict on a decisive applicability fact")
    elif outcome == "P-RV-F" and inp.fact_validation_failed:
        reasons.append("the extracted facts failed code validation twice")
    elif outcome == "P-RV-F":
        reasons.append("a required lookup failed with no cached fallback")
    low = bool(reasons)
    if inp.any_tool_failed and outcome != "P-RV-F":
        reasons.append("at least one tool call failed")
    if inp.assumptions_used:
        reasons.append("assumptions were used in applicability or scoring")
    if lk and lk["factors"]["reachability"]["defaulted"]:
        reasons.append("reachability was unknown and defaulted to 1")
    level = "Low" if low else "Medium" if reasons else "High"
    return {"level": level, "reasons": reasons or ["every factor is cited to a source"]}


# ---------------------------------------------------------------- Entry point

def evaluate(inp: PolicyInputs) -> dict:
    """Apply the full policy. Returns the decision and the scored rationale blocks."""
    status, outcome = gate_1(inp)

    lk = im = mx = None
    if outcome in ("Gate 2", "P-IE") and gate_2_available(inp):
        lk, im = likelihood(inp), impact(inp)
        mx = matrix(lk, im)
    elif outcome == "Gate 2":
        raise ValueError("Applicability confirmed but Gate 2 inputs (CVSS metrics, criticality, blast radius) are missing")

    if outcome == "Gate 2":
        decision = {"rating": mx["rating"], "policy_rule_applied": mx["policy_rule"], "gate_reached": "Gate 2", "provisional": None}
        gate_2_status = "evaluated"
    else:
        rating = {"P-NA": "Low", "P-IE": "Insufficient Evidence"}.get(outcome, "Review Needed")
        provisional = None
        if outcome == "P-IE" and mx:
            provisional = {"rating": mx["rating"], "policy_rule": mx["policy_rule"], "binding": False}
        decision = {"rating": rating, "policy_rule_applied": outcome, "gate_reached": "Gate 1", "provisional": provisional}
        gate_2_status = "provisional" if provisional else "not_evaluated"
        if not provisional:
            lk = im = mx = None

    return {
        "policy_version": POLICY_VERSION,
        "decision": decision,
        "applicability": {"status": status, "gate_1_outcome": outcome},
        "gate_2_status": gate_2_status,
        "likelihood": lk,
        "impact": im,
        "matrix_result": mx,
        "confidence": confidence(inp, outcome, lk),
    }


def parse_cvss_vector(vector: str) -> dict[str, str]:
    """'CVSS:3.1/AV:N/AC:L/...' -> {'AV': 'N', 'AC': 'L', ...}"""
    parts = [p.split(":", 1) for p in vector.split("/") if ":" in p]
    return {k: v for k, v in parts if k != "CVSS"}
