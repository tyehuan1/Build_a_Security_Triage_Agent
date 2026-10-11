"""Policy tests. The first four map to the Assignment 2 policy checks.

Baseline = the W01 / CVE-2026-69730 facts: internal reachability, network
unauthenticated RCE (AV:N/AC:L/PR:N/UI:N, C/I/A High), not in KEV, vendor
'Exploitation More Likely', critical Tier 0 asset, domain-wide blast radius,
RTO 4h. Expected values are set from the group's documented policy.
"""

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy import PolicyInputs, evaluate, exploitability_score  # noqa: E402

CVSS = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "H", "I": "H", "A": "H"}


def baseline(**changes) -> PolicyInputs:
    base = PolicyInputs(
        conditions={"C1": "true", "C2": "true", "C3": "unknown"},
        reachability=1, cvss_metrics=CVSS,
        kev_listed=False, credible_in_the_wild=False, public_poc=None, vendor_exploitation_likely=True,
        asset_criticality=2, blast_radius=2, rto_hours=4,
    )
    return replace(base, **changes)


# ---------------------------------------------------------------- baseline run

def test_baseline_is_insufficient_evidence_with_provisional_high():
    r = evaluate(baseline())
    assert r["decision"]["rating"] == "Insufficient Evidence"
    assert r["decision"]["policy_rule_applied"] == "P-IE"
    assert r["decision"]["provisional"] == {"rating": "High", "policy_rule": "P-H-L4I2", "binding": False}
    assert r["gate_2_status"] == "provisional"


# ---------------------------------------------------------------- policy check 1: applicability change (impact held constant)

@pytest.mark.parametrize("c3, rating, rule", [
    ("true", "High", "P-H-L4I2"),   # a DC is below 10.0.20348.5622
    ("false", "Low", "P-NA"),       # all DCs patched
])
def test_applicability_change(c3, rating, rule):
    r = evaluate(baseline(conditions={"C1": "true", "C2": "true", "C3": c3}))
    assert (r["decision"]["rating"], r["decision"]["policy_rule_applied"]) == (rating, rule)


# ---------------------------------------------------------------- policy check 2: impact change (applicability held constant)

def test_impact_change():
    confirmed = {"C1": "true", "C2": "true", "C3": "true"}
    high = evaluate(baseline(conditions=confirmed))
    lower = evaluate(baseline(conditions=confirmed, asset_criticality=1, blast_radius=1, rto_hours=8))
    assert high["decision"]["policy_rule_applied"] == "P-H-L4I2"
    assert lower["decision"]["policy_rule_applied"] == "P-M-L4I1"
    assert lower["likelihood"] == high["likelihood"]  # only impact moved


# ---------------------------------------------------------------- policy check 3: missing / conflicting evidence

def test_missing_evidence_is_insufficient_evidence():
    r = evaluate(baseline())  # C3 unknown
    assert r["decision"]["rating"] == "Insufficient Evidence"


def test_conflicting_evidence_is_review_needed():
    r = evaluate(baseline(conditions={"C1": "true", "C2": "true", "C3": "conflicting"}))
    assert (r["decision"]["rating"], r["decision"]["policy_rule_applied"]) == ("Review Needed", "P-RV-C")
    assert r["likelihood"] is None  # no provisional rating on conflict


# ---------------------------------------------------------------- controlled failure

def test_decisive_tool_failure_is_review_needed():
    r = evaluate(baseline(decisive_tool_failure=True, cvss_metrics=None))
    assert (r["decision"]["rating"], r["decision"]["policy_rule_applied"]) == ("Review Needed", "P-RV-F")


def test_confirmed_false_wins_over_tool_failure():
    r = evaluate(baseline(conditions={"C1": "true", "C2": "false", "C3": "unknown"}, decisive_tool_failure=True))
    assert r["decision"]["policy_rule_applied"] == "P-NA"


# ---------------------------------------------------------------- likelihood rules

def test_kev_sets_exploit_activity_to_2():
    r = evaluate(baseline(conditions={"C1": "true", "C2": "true", "C3": "true"}, kev_listed=True))
    assert r["likelihood"]["factors"]["exploit_activity"]["score"] == 2
    assert r["likelihood"]["final_score"] == 5


def test_unknown_reachability_defaults_to_1():
    r = evaluate(baseline(reachability=None))
    assert r["likelihood"]["factors"]["reachability"] == {"score": 1, "defaulted": True}


def test_isolated_asset_caps_likelihood_at_1():
    r = evaluate(baseline(conditions={"C1": "true", "C2": "true", "C3": "true"}, reachability=0, kev_listed=True))
    assert r["likelihood"]["raw_sum"] == 4
    assert r["likelihood"]["final_score"] == 1
    assert r["likelihood"]["reachability_cap_applied"] is True


@pytest.mark.parametrize("metrics, score", [
    ({"AV": "L", "AC": "L", "PR": "N", "UI": "N"}, 0),
    ({"AV": "N", "AC": "H", "PR": "N", "UI": "N"}, 1),
    ({"AV": "A", "AC": "L", "PR": "N", "UI": "N"}, 2),
])
def test_exploitability(metrics, score):
    assert exploitability_score(metrics) == score


# ---------------------------------------------------------------- impact adjustments

def test_rto_adjustment_not_binding_at_max_impact():
    adj = {a["id"]: a for a in evaluate(baseline())["impact"]["adjustments"]}
    assert adj["ADJ-RTO"]["triggered"] and not adj["ADJ-RTO"]["binding"]


def test_rto_adjustment_binding_below_max():
    r = evaluate(baseline(asset_criticality=1, blast_radius=1, rto_hours=4))
    assert r["impact"]["final_score"] == 2
    assert {a["id"]: a for a in r["impact"]["adjustments"]}["ADJ-RTO"]["binding"]


def test_unknown_rto_makes_no_adjustment():
    adj = {a["id"]: a for a in evaluate(baseline(rto_hours=None))["impact"]["adjustments"]}
    assert adj["ADJ-RTO"]["input_status"] == "unknown" and not adj["ADJ-RTO"]["triggered"]


def test_low_cia_reduces_impact():
    low = {**CVSS, "C": "L", "I": "N", "A": "L"}
    r = evaluate(baseline(cvss_metrics=low, rto_hours=8))
    assert r["impact"]["final_score"] == 1


# ---------------------------------------------------------------- input guards

def test_invalid_condition_value_rejected():
    with pytest.raises(ValueError):
        PolicyInputs(conditions={"C1": "maybe"})


def test_confirmed_without_gate_2_inputs_raises():
    with pytest.raises(ValueError):
        evaluate(baseline(conditions={"C1": "true", "C2": "true", "C3": "true"}, cvss_metrics=None))
