"""Analyst review tests: review rules, locator resolution, review sheet, and re-validation."""

import copy
import json
import subprocess
import sys

import pytest

import config
from review import MISSING, ReviewError, _excerpt, apply_review, resolve, review_sheet
from validate import check_analyst_review

ROOT = config.ROOT
EXAMPLE = json.loads((ROOT / "tests/fixtures/assessment_example_CVE-2026-69730_W01.json").read_text(encoding="utf-8"))


def review(**kw):
    base = dict(reviewer="Ty", status="approved", citations_verified=True, agrees=True,
                consensus="Insufficient Evidence", notes="Checked E1-E10 against tool outputs.")
    return apply_review(copy.deepcopy(EXAMPLE), **{**base, **kw})


def test_approved_review_is_recorded_and_valid():
    a = review()
    r = a["analyst_review"]
    assert (r["status"], r["reviewer"], r["citations_verified"], r["agrees_with_rating"]) == ("approved", "Ty", True, True)
    assert r["reviewed_at"] and check_analyst_review(a) == []


@pytest.mark.parametrize("kw, msg", [
    ({"agrees": False}, "use 'changed' or 'rejected'"),
    ({"citations_verified": False}, "use 'changed' or 'rejected'"),
    ({"status": "changed", "notes": ""}, "requires notes"),
    ({"status": "rejected", "notes": None}, "requires notes"),
    ({"status": "changed", "consensus": None}, "consensus rating"),
    ({"reviewer": ""}, "reviewer name"),
    ({"consensus": "Critical"}, "consensus rating must be"),
])
def test_review_rules(kw, msg):
    with pytest.raises(ReviewError, match=msg):
        review(**kw)


def test_override_with_justification_is_valid():
    a = review(status="changed", agrees=False, consensus="High", notes="A DC build was confirmed below the fix.")
    assert check_analyst_review(a) == []


def test_validator_flags_hand_edited_review():
    a = copy.deepcopy(EXAMPLE)
    a["analyst_review"].update(status="approved", reviewer="Ty", reviewed_at="2026-10-12T00:00:00-04:00",
                               citations_verified=False, agrees_with_rating=True)
    assert check_analyst_review(a)


@pytest.mark.parametrize("locator, expected", [
    ("cvss.vector", "CVSS:3.1/AV:N"),
    ("result.cvss.vector", "CVSS:3.1/AV:N"),
    ("affected[product='Windows Server 2022'].fixed_build", "10.0.20348.5622"),
    ("assets[asset_id=W01].platform.os", "Windows Server 2022"),
    ("results[0].url", "https://msrc"),
])
def test_resolve(locator, expected):
    result = {"cvss": {"vector": "CVSS:3.1/AV:N/AC:L"},
              "affected": [{"product": "Windows Server 2016", "fixed_build": "x"},
                           {"product": "Windows Server 2022", "fixed_build": "10.0.20348.5622"}],
              "records": [{"locator": "assets[asset_id=W01]", "data": {"platform": {"os": "Windows Server 2022"}}}],
              "results": [{"url": "https://msrc.microsoft.com/x"}]}
    assert str(resolve(result, locator)).startswith(expected)


def test_resolve_distinguishes_null_from_missing():
    result = {"records": [{"locator": "assets[asset_id=W01]", "data": {"platform": {"os_build": None}}}]}
    assert resolve(result, "assets[asset_id=W01].data.platform.os_build") is None   # real null (unknown)
    assert resolve(result, "assets[asset_id=W01].platform.nope") is MISSING
    assert _excerpt(None) == "null (unknown)"


def test_excerpt_centres_on_the_quoted_fact():
    text = "CVSS metric boilerplate. " * 60 + "Exploitability assessment Exploitation More Likely ## FAQ"
    out = _excerpt(text, "Microsoft reports 'Exploitation More Likely'.")
    assert "Exploitation More Likely" in out and out.startswith("... ")


def test_excerpt_centres_list_on_the_product_named_in_the_fact():
    affected = [{"product": f"Windows 10 Version {v}", "fixed_build": "x" * 40} for v in range(8)] + \
               [{"product": "Windows Server 2022", "fixed_build": "10.0.20348.5622"}]
    out = _excerpt(affected, "Windows Server 2022 is listed as an affected product.")
    assert "Windows Server 2022" in out and "10.0.20348.5622" in out


def test_review_sheet_on_baseline_shows_saved_values():
    path = ROOT / "model_outputs_and_assessments/baseline/assessment.json"
    if not path.is_file():
        pytest.skip("baseline run not present")
    a = json.loads(path.read_text(encoding="utf-8"))
    sheet = review_sheet(a)
    assert "## Evidence" in sheet and all(e["evidence_id"] in sheet for e in a["evidence"])
    assert "10.0.20348.5622" in sheet and "not resolvable" not in sheet.split("## Evidence")[1].split("## Assumptions")[0]


def test_cli_records_review_on_a_copy(tmp_path):
    a = copy.deepcopy(EXAMPLE)
    target = tmp_path / "assessment.json"
    target.write_text(json.dumps(a), encoding="utf-8")
    cmd = [sys.executable, str(ROOT / "review.py"), str(target), "--reviewer", "Ty", "--status", "approved",
           "--citations-verified", "yes", "--agrees", "yes", "--consensus", "Insufficient Evidence", "--notes", "ok"]
    out = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0, out.stdout + out.stderr
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["analyst_review"]["status"] == "approved"
    assert all(c["passed"] for c in saved["validation"]["checks"])
    assert (tmp_path / "other_info" / "review_sheet.md").is_file()
