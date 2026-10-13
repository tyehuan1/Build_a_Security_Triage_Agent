"""End-to-end workflow tests with a scripted model (no network).

CVE / NVD / KEV are served from the caches via fault injection; Tavily is a fake network route.
The scripted model makes the tool calls a real model would; the real ToolRunner executes them.
"""

import copy
import json

import pytest

from fakes import FakeResponse, LLMError, ScriptedLLM, reply
from orchestrator import run_assessment
from validate import check_model_tool_calls

CVE = "CVE-2026-69730"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
MSRC_URL = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69730"
MSRC_SNIPPET = ("Use after free in Windows DNS allows an unauthorized attacker to execute code over a network. "
                "## Exploitability Publicly disclosed No Exploited No Exploitability assessment Exploitation More Likely. "
                "Security update KB5122882 (build 10.0.20348.5622).")


def cit(call_id, locator, fact="supporting fact"):
    return {"call_id": call_id, "locator": locator, "fact": fact}


# T1 lookup_vulnerability, T2 env asset W01, T3 lookup_kev
PLAN_1 = [("lookup_vulnerability", {"cve_id": CVE}), ("environment_search", {"query_type": "asset", "query": "W01"}),
          ("lookup_kev", {"cve_id": CVE})]
# T4 env text, T5 env flows, T6 env business service, T7 tavily
PLAN_2 = [("environment_search", {"query_type": "text", "query": "DNS Server"}),
          ("environment_search", {"query_type": "flows", "query": "W01"}),
          ("environment_search", {"query_type": "business_service", "query": "W01"}),
          ("tavily_search", {"query": f"{CVE} exploitability exploited in the wild", "allowed_domains": ["msrc.microsoft.com"],
                             "max_results": 3})]
DONE = "EVIDENCE GATHERING COMPLETE\n1. T1\n2. T2\n3. T4\n4. T5\n5. T6\n6. T3\n7. T7"


def plan_script():
    return [reply(tool_calls=PLAN_1), reply(tool_calls=PLAN_2), reply(DONE)]


def good_facts():
    return {
        "asset": {"asset_id": "W01", "asset_name": "Domain controllers", "services": ["AD DS", "DNS Server", "Kerberos", "Group Policy"],
                  "host_count": 4, "sites": {"HQ": 2, "RECOVERY": 2}, "tier": "Tier 0", "operating_system": "Windows Server 2022",
                  "os_build": None, "network_zone": "IDENTITY", "subnets": ["10.20.20.0/24"],
                  "citations": [cit("T2", "assets[asset_id=W01]", "W01 is 4 Windows Server 2022 DCs; os_build is null.")]},
        "scope_check": {"query": "Do other assets run DNS Server?", "result": "No; only W01 of 44 assets.",
                        "citations": [cit("T4", "coverage", "Only W01 matches 'DNS Server'; register complete at cohort level.")]},
        "threat": {"cve_id": CVE, "title": "Windows DNS Server Remote Code Execution Vulnerability",
                   "affected_component": "Windows DNS Server service", "affected_products_relevant": ["Windows Server 2022"],
                   "fix": {"kb": "KB5122882", "fixed_build": "10.0.20348.5622"},
                   "citations": [cit("T1", "affected[product='Windows Server 2022'].fixed_build", "Fixed in 10.0.20348.5622."),
                                 cit("T7", "results[0].snippet", "KB5122882 is the security update.")]},
        "technical_severity": {"cvss_version": "3.1", "base_score": 9.8, "base_severity": "Critical", "vector": VECTOR,
                               "source": "Microsoft (CNA)", "citations": [cit("T1", "cvss.vector", "CVSS 3.1 9.8 AV:N/AC:L/PR:N/UI:N.")]},
        "conditions": [
            {"id": "C1", "result": "true", "basis": "Server 2022 is affected; W01 runs Server 2022.",
             "citations": [cit("T1", "affected[product='Windows Server 2022']", "Server 2022 affected."),
                           cit("T2", "assets[asset_id=W01].platform.os", "W01 OS is Windows Server 2022.")]},
            {"id": "C2", "result": "true", "basis": "W01 lists DNS Server.",
             "citations": [cit("T2", "assets[asset_id=W01].services", "DNS Server is a W01 service.")]},
            {"id": "C3", "result": "unknown", "basis": "os_build is null.",
             "citations": [cit("T2", "assets[asset_id=W01].platform.os_build", "os_build is null.")]},
        ],
        "likelihood": {
            "reachability": {"value": 1, "basis": "Internal domain-joined devices reach W01 on DNS (F09); not Internet-published.",
                             "citations": [cit("T5", "flows[flow_id=F09]", "All internal zones reach W01 on 53/tcp+udp.")]},
            "exploit_activity": {"kev_listed": False, "credible_in_the_wild": False, "public_poc": False,
                                 "vendor_exploitation_likely": True, "vendor_exploitability_assessment": "Exploitation More Likely",
                                 "basis": "Not in KEV; Microsoft rates Exploitation More Likely.",
                                 "citations": [cit("T3", "in_kev", "Not in KEV."),
                                               cit("T7", "results[0].snippet", "MSRC: Exploitation More Likely.")]}},
        "impact": {
            "asset_criticality": {"value": 2, "basis": "Tier 0 identity infrastructure.",
                                  "citations": [cit("T2", "assets[asset_id=W01]", "W01 is Tier 0.")]},
            "blast_radius": {"value": 2, "basis": "Single domain; DC compromise is organization-wide.",
                             "citations": [cit("T2", "assets[asset_id=W01].config_notes", "One forest, one domain.")]},
            "rto_hours": {"value": 4, "basis": "BS01 RTO 4h.",
                          "citations": [cit("T6", "business_services[service_id=BS01]", "BS01 RTO is 4 hours.")]}},
        "assumptions": [{"statement": "All four DCs run DNS Server.", "reason": "Cohort record.", "affects": ["applicability.C2"]}],
        "unknowns": [{"question": "What OS build is on each DC?", "decisive": True, "condition_id": "C3",
                      "why_it_matters": "Decides C3.", "default_applied": "None.", "how_to_resolve": "Query each DC build."}],
        "conflicts": [],
        "other_factors": ["Four DCs across two sites."],
    }


def explanation():
    return {"decision_summary": "C3 is unknown, so no binding rating; provisional High.",
            "provisional_condition": "Applies if any W01 DC is below 10.0.20348.5622.",
            "severity_vs_local_risk": "CVSS 9.8 Critical; local risk depends on the DC builds.",
            "confidence_explanation": "Low because the decisive OS build is unknown.",
            "action": {"recommended_next_step": "Check the OS build on all four DCs.", "priority": "High",
                       "owner": "Identity team", "interim_measures": ["Restrict port 53 to required segments."],
                       "evidence_to_resolve": [{"evidence_needed": "All DCs >= 10.0.20348.5622", "effect_on_decision": "C3 false -> Low (P-NA)"}]}}


@pytest.fixture
def env_settings(settings, net, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "test-key")
    settings["fault_injection"].update(cve=True, nvd=True, kev=True)
    net(routes={"tavily": FakeResponse(200, {"request_id": "req-1", "results": [
        {"title": "CVE-2026-69730 Windows DNS Server RCE", "url": MSRC_URL, "content": MSRC_SNIPPET, "published_date": None}]})})
    return settings


def run(settings, tmp_path, *script):
    llm = ScriptedLLM(*script)
    result = run_assessment(settings, llm_factory=llm.attach, runs_dir=tmp_path, run_id="test-run")
    return result, llm


def failed_checks(assessment):
    return [c for c in assessment["validation"]["checks"] if not c["passed"]]


# ---------------------------------------------------------------- complete run

def test_complete_run_gives_insufficient_evidence_with_provisional_high(env_settings, tmp_path):
    result, llm = run(env_settings, tmp_path, *plan_script(), good_facts(), explanation())
    a = result["assessment"]
    assert result["status"] == "completed", failed_checks(a)
    assert (a["decision"]["rating"], a["decision"]["policy_rule_applied"]) == ("Insufficient Evidence", "P-IE")
    assert a["decision"]["provisional"]["policy_rule"] == "P-H-L4I2"
    assert a["confidence"]["level"] == "Low"
    assert a["decision"]["missing_decisive_facts"] == ["U1"]
    # tools were really executed: 7 model-selected calls with saved, hashed raw outputs
    assert [t["call_id"] for t in a["tool_trace"]] == [f"T{i}" for i in range(1, 8)]
    assert all(t["selected_by"] == "model" and t["output_sha256"] and t["model_call_id"] for t in a["tool_trace"])
    # evidence provenance comes from the trace, not the model
    e_kev = next(e for e in a["evidence"] if e["tool_call_id"] == "T3")
    assert (e_kev["source_type"], e_kev["retrieval_mode"]) == ("kev", "cached") and e_kev["fallback_reason"]
    e_env = next(e for e in a["evidence"] if e["tool_call_id"] == "T2")
    assert (e_env["retrieval_mode"], e_env["url_or_path"]) == ("simulated", "Resources/windows_enterprise_environment.json")
    e_cve = next(e for e in a["evidence"] if e["tool_call_id"] == "T1")
    assert (e_cve["retrieval_mode"], e_cve["url_or_path"]) == (
        "cached", "https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/69xxx/CVE-2026-69730.json")  # manifest source
    assert "role" in a["run_metadata"]["threat_input"]
    e_web = next(e for e in a["evidence"] if e["tool_call_id"] == "T7")
    assert (e_web["source_type"], e_web["url_or_path"]) == ("vendor_advisory", MSRC_URL)
    # run record
    run_dir = result["run_dir"]
    assert (run_dir / "assessment.json").is_file()
    for name in ("config.json", "prompts.json", "inputs.json", "run_log.jsonl", "model_transcript.jsonl"):
        assert (run_dir / "other_info" / name).is_file(), name
    assert len(list((run_dir / "tool_outputs").glob("T*.json"))) == 7
    # LF line endings on every OS, so saved bytes (and their SHA-256) survive git and cross-platform clones
    assert not [p.name for p in run_dir.rglob("*.json*") if b"\r\n" in p.read_bytes()]
    # the model saw each tool result tagged with its call ID
    tool_msgs = [m for m in llm.requests[1]["messages"] if m["role"] == "tool"]
    assert [json.loads(m["content"])["call_id"] for m in tool_msgs] == ["T1", "T2", "T3"]


# ---------------------------------------------------------------- anti-fabrication

def test_fabricated_tool_output_is_rejected_and_never_becomes_evidence(env_settings, tmp_path):
    fake = reply('lookup_kev(cve_id="CVE-2026-69730") -> {"status": "found", "in_kev": true}')
    result, llm = run(env_settings, tmp_path, fake, *plan_script(), good_facts(), explanation())
    a = result["assessment"]
    assert result["status"] == "completed", failed_checks(a)
    assert len(a["run_metadata"]["fabrication_rejections"]) == 1
    assert "rejected" in llm.requests[1]["messages"][-1]["content"]
    assert len(a["tool_trace"]) == 7 and a["rationale"]["likelihood"]["factors"]["exploit_activity"]["kev_listed"] is False


def test_result_prefix_on_locators_is_accepted(env_settings, tmp_path):
    f = good_facts()
    f["technical_severity"]["citations"] = [cit("T1", "result.cvss.vector", "CVSS vector.")]
    result, _ = run(env_settings, tmp_path, *plan_script(), f, explanation())
    assert result["assessment"]["run_metadata"]["fact_validation"]["attempts"][0]["passed"] is True


def test_scope_unknown_without_a_service_search_is_accepted(env_settings, tmp_path):
    f = good_facts()
    f["scope_check"].update(result="Unknown: no search for DNS Server across assets was run.", citations=[])
    result, _ = run(env_settings, tmp_path, *plan_script(), f, explanation())
    assert result["assessment"]["run_metadata"]["fact_validation"]["attempts"][0]["passed"] is True


def test_invented_call_id_is_caught_and_corrected(env_settings, tmp_path):
    bad = good_facts()
    bad["likelihood"]["exploit_activity"]["citations"].append(cit("T99", "in_kev", "KEV says so."))
    result, llm = run(env_settings, tmp_path, *plan_script(), bad, good_facts(), explanation())
    fv = result["assessment"]["run_metadata"]["fact_validation"]
    assert [x["passed"] for x in fv["attempts"]] == [False, True]
    assert any("T99" in p for p in fv["attempts"][0]["problems"])
    assert "T99" in llm.requests[-2]["messages"][-1]["content"]  # the retry prompt listed the problem
    assert result["assessment"]["decision"]["policy_rule_applied"] == "P-IE"


def test_fact_not_returned_by_tools_twice_gives_review_needed(env_settings, tmp_path):
    bad = good_facts()
    bad["technical_severity"]["vector"] = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"  # not what T1 returned
    result, _ = run(env_settings, tmp_path, *plan_script(), bad, copy.deepcopy(bad), explanation())
    a = result["assessment"]
    assert result["status"] == "completed", failed_checks(a)
    assert (a["decision"]["rating"], a["decision"]["policy_rule_applied"]) == ("Review Needed", "P-RV-F")
    assert a["run_metadata"]["fact_validation"]["passed"] is False


@pytest.mark.parametrize("mutate, expect", [
    (lambda f: f["likelihood"]["exploit_activity"].update(kev_listed=True), "kev_listed"),
    (lambda f: f["conditions"][2].update(result="true"), "C3 is 'true'"),
    (lambda f: f["impact"]["rto_hours"].update(value=2), "rto_hours"),
    (lambda f: f["likelihood"]["reachability"].update(value=2), "internet_exposure"),
    (lambda f: f["threat"]["fix"].update(fixed_build="10.0.20348.9999"), "fixed_build"),
    (lambda f: f["asset"].update(os_build="10.0.20348.100"), "os_build"),
    (lambda f: f["conditions"][0]["citations"].__setitem__(0, cit("T5", "assets[asset_id=W01]", "x")), "does not point inside"),
    (lambda f: f["scope_check"].update(citations=[cit("T1", "affected", "x")]), "scope_check: must cite an environment_search"),
    # the coverage of an asset-ID lookup (T2) only shows which assets matched the ID, not who runs DNS Server
    (lambda f: f["scope_check"].update(citations=[cit("T2", "coverage", "Only W01 matched.")]), "text search for 'DNS Server'"),
])
def test_fact_checks_catch_unsupported_facts(env_settings, tmp_path, mutate, expect):
    bad = good_facts()
    mutate(bad)
    result, _ = run(env_settings, tmp_path, *plan_script(), bad, good_facts(), explanation())
    problems = result["assessment"]["run_metadata"]["fact_validation"]["attempts"][0]["problems"]
    assert any(expect in p for p in problems), problems


def test_validator_catches_trace_entry_not_requested_by_model(env_settings, tmp_path):
    result, _ = run(env_settings, tmp_path, *plan_script(), good_facts(), explanation())
    a = copy.deepcopy(result["assessment"])
    assert check_model_tool_calls(a) == []
    a["tool_trace"][0]["model_call_id"] = "call_never_made"
    problems = check_model_tool_calls(a)
    assert any("not a structured tool call" in p for p in problems)
    assert any("has no trace entry" in p for p in problems)


# ---------------------------------------------------------------- failure paths

def no_vuln_facts():
    f = good_facts()
    f["threat"].update(fix={"kb": None, "fixed_build": None}, citations=[])
    f["technical_severity"] = {"cvss_version": None, "base_score": None, "base_severity": None, "vector": None,
                               "source": None, "citations": []}
    f["conditions"][0] = {"id": "C1", "result": "unknown", "basis": "lookup_vulnerability failed.", "citations": []}
    f["likelihood"]["exploit_activity"].update(kev_listed=None, citations=[cit("T7", "results[0].snippet", "MSRC: More Likely.")])
    f["unknowns"].append({"question": "Is Server 2022 affected?", "decisive": True, "condition_id": "C1",
                          "why_it_matters": "Decides C1.", "default_applied": "None.", "how_to_resolve": "Retry the CVE/NVD lookup."})
    return f


def test_vulnerability_lookup_outage_gives_review_needed(env_settings, tmp_path):
    env_settings["fault_injection"]["disable_cache"] = True
    script = [*plan_script()[:2],
              reply("Done. EVIDENCE GATHERING COMPLETE"),
              reply(tool_calls=[("lookup_vulnerability", {"cve_id": CVE})]),  # completeness follow-up
              reply("EVIDENCE GATHERING COMPLETE; lookup_vulnerability unavailable."),
              no_vuln_facts(), explanation()]
    result, llm = run(env_settings, tmp_path, *script)
    a = result["assessment"]
    assert result["status"] == "completed", failed_checks(a)
    assert (a["decision"]["rating"], a["decision"]["policy_rule_applied"]) == ("Review Needed", "P-RV-F")
    assert a["run_metadata"]["completeness"] == {"required": ["environment_search", "lookup_vulnerability"],
                                                 "followed_up": True, "missing": ["lookup_vulnerability"]}
    assert [t["result_status"] for t in a["tool_trace"] if t["tool"] == "lookup_vulnerability"] == ["failed", "failed"]
    assert any("required lookups have not succeeded" in m["content"] for m in llm.requests[3]["messages"] if m["role"] == "user")
    assert a["confidence"]["level"] == "Low"


def test_model_outage_stops_with_review_needed(env_settings, tmp_path):
    result, _ = run(env_settings, tmp_path, LLMError("model call 'plan-1' failed after 2 attempt(s): HTTP 503"))
    assert (result["status"], result["stage"]) == ("stopped", "plan")
    failure = json.loads(result["failure_path"].read_text())
    assert (failure["rating"], failure["policy_rule_applied"]) == ("Review Needed", "P-RV-F")


def test_malformed_cve_stops_at_intake_without_calling_the_model(env_settings, tmp_path):
    env_settings["inputs"]["cve_id"] = "CVE-26-1"
    result, llm = run(env_settings, tmp_path)
    assert (result["status"], result["stage"]) == ("stopped", "intake") and llm.requests == []


def test_placeholder_folder_is_used_but_a_previous_run_is_never_overwritten(env_settings, tmp_path):
    (tmp_path / "test-run").mkdir()
    (tmp_path / "test-run" / ".gitkeep").touch()
    result, _ = run(env_settings, tmp_path, *plan_script(), good_facts(), explanation())
    assert result["status"] == "completed" and not (tmp_path / "test-run" / ".gitkeep").exists()
    with pytest.raises(FileExistsError):
        run(env_settings, tmp_path, *plan_script(), good_facts(), explanation())


def test_missing_environment_file_stops_at_intake(env_settings, tmp_path):
    env_settings["inputs"]["environment_snapshot"]["path"] = "Resources/does_not_exist.json"
    result, _ = run(env_settings, tmp_path)
    assert (result["status"], result["stage"]) == ("stopped", "intake") and "not found" in result["reason"]
