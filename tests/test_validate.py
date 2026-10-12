"""Validator tests: the example passes, and deliberately broken copies fail the right check."""

import copy
import json
from pathlib import Path

import pytest

from validate import validate_assessment

ROOT = Path(__file__).resolve().parents[1]

SCHEMA = json.loads((ROOT / "Resources" / "output_schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((ROOT / "tests" / "fixtures" / "assessment_example_CVE-2026-69730_W01.json").read_text(encoding="utf-8"))
POLICY_CHECK = "Decision, scores, matrix and confidence match policy.py"


def failed_checks(a):
    report = validate_assessment(a, SCHEMA)
    return {c["check"] for c in report["checks"] if not c["passed"]}


def test_example_passes():
    assert failed_checks(EXAMPLE) == set()


def broken(fn):
    a = copy.deepcopy(EXAMPLE)
    fn(a)
    return failed_checks(a)


def _set_kev_true_but_score_1(a):
    a["rationale"]["likelihood"]["factors"]["exploit_activity"]["kev_listed"] = True


def _wrong_rating(a):
    a["decision"]["rating"] = "High"


def _cite_missing_evidence(a):
    a["rationale"]["applicability"]["conditions"][0]["evidence_ids"].append("E99")


def _cached_without_reason(a):
    next(e for e in a["evidence"] if e["retrieval_mode"] == "cached")["fallback_reason"] = None


def _env_evidence_labeled_live(a):
    next(e for e in a["evidence"] if e["source_type"] == "environment_snapshot")["retrieval_mode"] = "live"


def _env_search_without_query(a):
    del next(t for t in a["tool_trace"] if t["tool"] == "environment_search")["arguments"]["query"]


def _vuln_lookup_failed_but_not_review(a):
    next(t for t in a["tool_trace"] if t["tool"] == "lookup_vulnerability")["result_status"] = "failed"


def _bad_matrix(a):
    a["rationale"]["matrix_result"]["policy_rule"] = "P-M-L4I2"


def _missing_field(a):
    del a["action"]


def _wrong_confidence(a):
    a["confidence"]["level"] = "High"


def _evidence_from_failed_call(a):
    next(t for t in a["tool_trace"] if t["evidence_ids"])["result_status"] = "failed"


@pytest.mark.parametrize("mutate, expected_check", [
    (_set_kev_true_but_score_1, POLICY_CHECK),
    (_wrong_rating, POLICY_CHECK),
    (_bad_matrix, POLICY_CHECK),
    (_vuln_lookup_failed_but_not_review, POLICY_CHECK),
    (_wrong_confidence, POLICY_CHECK),
    (_cite_missing_evidence, "Every cited evidence_id exists and every evidence item is cited"),
    (_evidence_from_failed_call, "Every evidence item comes from a successful call in tool_trace"),
    (_cached_without_reason, "Cached evidence has a fallback reason; environment evidence is labeled simulated"),
    (_env_evidence_labeled_live, "Cached evidence has a fallback reason; environment evidence is labeled simulated"),
    (_env_search_without_query, "Tool calls follow the tool contracts"),
    (_missing_field, "Output matches output_schema.json"),
])
def test_broken_copies_fail(mutate, expected_check):
    assert expected_check in broken(mutate)
