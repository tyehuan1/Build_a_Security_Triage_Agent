"""Tool contract tests (offline). External sources are served from the caches via fault injection
or from a fake network; environment_search runs on the real environment snapshot."""

import hashlib
import json
from pathlib import Path

import pytest

import config
from fakes import FakeResponse
from tools import environment_search, lookup_kev, lookup_vulnerability, tavily_search
from tools.registry import ToolRunner, load_raw_output
from validate import check_raw_outputs, check_tool_contracts

CVE = "CVE-2026-69730"
ENV_PATH = "Resources/windows_enterprise_environment.json"


@pytest.fixture(scope="module")
def env():
    return json.loads(config.path(ENV_PATH).read_text(encoding="utf-8"))


@pytest.fixture
def cached(settings, net):
    """Settings where CVE, NVD and KEV are 'down', so tools use the caches with no network."""
    settings["fault_injection"].update(cve=True, nvd=True, kev=True)
    net()  # any real network call would raise
    return settings


def search(env, qtype, query, max_results=10):
    return environment_search.run({"query_type": qtype, "query": query, "max_results": max_results}, env, ENV_PATH)


def cache_json(settings, source):
    return json.loads(config.path(settings["sources"][source]["cache"]).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- environment_search

def test_env_asset_w01(env):
    out = search(env, "asset", "W01")
    rec = out.result["records"][0]
    assert (out.status, out.mode, len(out.result["records"])) == ("found", "simulated", 1)
    assert rec["locator"] == "assets[asset_id=W01]" and rec["basis"] == "stated"
    assert {"platform.os_build", "platform.installed_kbs"} <= set(rec["unknown_fields"])
    assert rec["data"]["platform"]["os"] == "Windows Server 2022"
    assert "DNS Server" in rec["data"]["services"]


def test_env_text_dns_server_only_w01_with_completeness(env):
    out = search(env, "text", "DNS Server")
    cov = out.result["coverage"]
    assert cov["matching_asset_ids"] == ["W01"] and cov["assets_searched"] == 44
    assert "complete at cohort level" in cov["completeness_statement"]
    assert cov["completeness_locator"] == "evidence[evidence_id=S06]"


def test_env_flows_w01(env):
    recs = search(env, "flows", "W01", max_results=25).result["records"]
    ids = {r["record_id"] for r in recs}
    assert {"F09", "F10", "IDENTITY", "network.default_policy", "network.public_services"} <= ids
    assert any(r["record_type"] == "denied_path" and "W08" in r["data"]["source"] for r in recs)
    public = next(r for r in recs if r["record_type"] == "public_exposure")
    assert "DNS" in public["data"]["not_published_to_internet"]


def test_env_business_service_by_asset(env):
    recs = search(env, "business_service", "W01").result["records"]
    bs01 = next(r for r in recs if r["record_id"] == "BS01")
    assert bs01["data"]["rto_hours"] == 4 and bs01["locator"] == "business_services[service_id=BS01]"


def test_env_not_found_and_truncation(env):
    assert search(env, "asset", "Z99").status == "not_found"
    out = search(env, "text", "W01", max_results=2)
    assert len(out.result["records"]) == 2 and out.result["truncated"] > 0


# ---------------------------------------------------------------- lookup_vulnerability

def test_vuln_from_caches(cached):
    out = lookup_vulnerability.run({"cve_id": CVE}, cached)
    r = out.result
    assert (out.status, out.mode, out.fallback_used, out.attempts) == ("found", "cached", True, 2)
    assert r["cvss"]["base_score"] == 9.8
    assert r["cvss"]["metrics"] == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    assert r["cvss"]["temporal"]["exploit_code_maturity"] == "U"
    s2022 = next(a for a in r["affected"] if a["product"] == "Windows Server 2022")
    assert s2022 == {"product": "Windows Server 2022", "version_start": "10.0.20348.0", "fixed_build": "10.0.20348.5622"}
    assert r["conflicts"] == []
    assert r["ssvc"]["Exploitation"] == "none"
    assert r["cwe"] == ["CWE-416"]
    assert all(s["mode"] == "cached" and s["fallback_reason"] for s in r["sources"])
    assert out.source_raw["cve"] and out.source_raw["nvd"]
    # cached data is cited to the original source recorded in the cache manifest, plus the cache file
    manifest = json.loads(config.path(cached["paths"]["cache_manifest"]).read_text(encoding="utf-8"))["files"]
    src = {s["name"]: s for s in r["sources"]}
    assert src["CVE"]["url"] == manifest[cached["sources"]["cve"]["cache"]]["source_url"]
    assert src["NVD"]["url"] == manifest[cached["sources"]["nvd"]["cache"]]["source_url"]
    assert src["CVE"]["cache_path"] == cached["sources"]["cve"]["cache"]


def test_vuln_mixed_live_and_cached(settings, net):
    settings["fault_injection"]["nvd"] = True
    live_url = "https://cveawg.mitre.org/api/cve/" + CVE
    net(routes={"cveawg": FakeResponse(200, cache_json(settings, "cve"), url=live_url)})
    out = lookup_vulnerability.run({"cve_id": CVE}, settings)
    assert (out.status, out.mode) == ("found", "mixed")
    src = {s["name"]: s for s in out.result["sources"]}
    assert (src["CVE"]["mode"], src["CVE"]["url"]) == ("live", live_url)  # cited to the URL actually fetched
    assert "cache_path" not in src["CVE"] and src["NVD"]["mode"] == "cached"


def test_vuln_one_source_failed_uses_the_other(settings, net):
    settings["fault_injection"].update(cve=True, disable_cache=True)
    net(routes={"services.nvd": FakeResponse(200, cache_json(settings, "nvd"))})
    out = lookup_vulnerability.run({"cve_id": CVE}, settings)
    assert (out.status, out.mode, out.fallback_used) == ("found", "live", True)
    assert any(n.startswith("CVE failed") for n in out.result["notes"])
    assert out.result["cvss"]["vector"].startswith("CVSS:3.1/AV:N/AC:L/PR:N/UI:N")


def test_vuln_both_failed_no_cache(settings, net):
    settings["fault_injection"].update(cve=True, nvd=True, disable_cache=True)
    net()
    out = lookup_vulnerability.run({"cve_id": CVE}, settings)
    assert (out.status, out.mode, out.result["status"]) == ("failed", None, "failed")
    assert "CVE:" in out.error and "NVD:" in out.error


def test_vuln_conflicting_fixed_build_is_flagged(cached, tmp_path):
    nvd = cache_json(cached, "nvd")
    for node in nvd["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"]:
        for cm in node["cpeMatch"]:
            if "windows_server_2022" in cm["criteria"]:
                cm["versionEndExcluding"] = "10.0.20348.5700"
    bad = tmp_path / "nvd_conflict.json"
    bad.write_text(json.dumps(nvd))
    manifest = json.loads(config.path(cached["paths"]["cache_manifest"]).read_text(encoding="utf-8"))
    manifest["files"][str(bad)] = {"source": "nvd", "saved_at": "2026-10-11T00:00:00-04:00",
                                   "sha256": hashlib.sha256(bad.read_bytes()).hexdigest()}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    cached["sources"]["nvd"]["cache"] = str(bad)
    cached["paths"]["cache_manifest"] = str(tmp_path / "manifest.json")
    out = lookup_vulnerability.run({"cve_id": CVE}, cached)
    assert len(out.result["conflicts"]) == 1
    assert "Windows Server 2022" in out.result["conflicts"][0] and "10.0.20348.5700" in out.result["conflicts"][0]


# ---------------------------------------------------------------- lookup_kev

def test_kev_not_listed_from_cache(cached):
    out = lookup_kev.run({"cve_id": CVE}, cached)
    assert (out.status, out.mode, out.result["in_kev"]) == ("not_found", "cached", False)
    assert out.result["catalog"]["catalog_version"] == "2026.10.08"
    assert out.result["fallback_reason"]
    assert out.source_raw == {"kev_catalog": out.result["catalog"], "kev_entry": None}


def test_kev_listed_live(settings, net):
    feed = {"catalogVersion": "test", "count": 1, "vulnerabilities": [
        {"cveID": CVE, "dateAdded": "2026-10-01", "requiredAction": "Apply updates", "dueDate": "2026-10-22",
         "knownRansomwareCampaignUse": "Unknown"}]}
    net(routes={"cisa.gov": FakeResponse(200, feed)})
    out = lookup_kev.run({"cve_id": CVE}, settings)
    r = out.result
    assert (out.status, out.mode, r["in_kev"], r["date_added"], r["due_date"]) == ("found", "live", True, "2026-10-01", "2026-10-22")


def test_kev_failed_without_cache(settings, net):
    settings["fault_injection"].update(kev=True, disable_cache=True)
    net()
    out = lookup_kev.run({"cve_id": CVE}, settings)
    assert (out.status, out.mode, out.result["in_kev"]) == ("failed", None, None)


# ---------------------------------------------------------------- tavily_search

def test_tavily_drops_results_off_allowlist(settings, net, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "k")
    net(routes={"tavily": FakeResponse(200, {"request_id": "r1", "results": [
        {"title": "MSRC", "url": "https://msrc.microsoft.com/update-guide/vulnerability/" + CVE, "content": "x" * 5000},
        {"title": "blog", "url": "https://random-blog.example/post", "content": "exploit!"}]})})
    out = tavily_search.run({"query": CVE, "allowed_domains": ["msrc.microsoft.com"], "max_results": 5}, settings)
    assert (out.status, out.mode) == ("found", "live")
    assert [r["title"] for r in out.result["results"]] == ["MSRC"]
    assert out.result["dropped_off_allowlist"] == 1
    assert len(out.result["results"][0]["snippet"]) == tavily_search.SNIPPET_CHARS
    assert out.result["request_id"] == "r1"


# ---------------------------------------------------------------- registry / runner

@pytest.fixture
def runner(cached, env, tmp_path):
    return ToolRunner(cached, env, ENV_PATH, tmp_path / "tool_outputs")


def test_runner_assigns_ids_and_saves_verifiable_raw_output(runner):
    p1 = runner.execute("environment_search", {"query_type": "asset", "query": "W01"}, model_call_id="call_a")
    p2 = runner.execute("lookup_kev", '{"cve_id": "CVE-2026-69730"}', model_call_id="call_b")  # string args are parsed
    assert (p1["call_id"], p2["call_id"]) == ("T1", "T2")
    t1, t2 = runner.trace
    assert t1["model_call_id"] == "call_a" and t2["arguments"] == {"cve_id": CVE}
    raw = load_raw_output(t1)
    assert raw["call_id"] == "T1" and raw["result"]["records"][0]["record_id"] == "W01"
    assert t2["receipts"][0]["mode"] == "cached" and t2["receipts"][0]["sha256"]
    assert check_raw_outputs({"tool_trace": runner.trace}) == []


def test_runner_detects_tampered_raw_output(runner):
    runner.execute("lookup_kev", {"cve_id": CVE})
    path = Path(runner.trace[0]["raw_output_path"])
    path = path if path.is_absolute() else config.ROOT / path
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["result"]["in_kev"] = True  # someone edits the saved evidence after the run
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert any("SHA-256" in p for p in check_raw_outputs({"tool_trace": runner.trace}))


def test_runner_invalid_args_one_correction_then_failed(runner):
    p1 = runner.execute("environment_search", {"query_type": "assets", "query": "W01"})
    p2 = runner.execute("environment_search", {"query_type": "asset"})
    p3 = runner.execute("environment_search", {"query_type": "asset", "query": "W01"})
    assert (p1["status"], p2["status"], p3["status"]) == ("invalid_request", "failed", "found")
    assert "query_type" in p1["error"] and "one correction" in p1["error"]
    assert check_tool_contracts({"tool_trace": runner.trace}) == []


def test_runner_rejects_off_allowlist_domain(runner):
    p = runner.execute("tavily_search", {"query": CVE, "allowed_domains": ["evil.example"], "max_results": 3})
    assert p["status"] == "invalid_request" and "allowlist" in p["error"]


def test_runner_rejects_bad_cve_id_and_extra_args(runner):
    assert runner.execute("lookup_kev", {"cve_id": "CVE-26-1"})["status"] == "invalid_request"
    assert runner.execute("lookup_vulnerability", {"cve_id": CVE, "verbose": True})["status"] == "invalid_request"


def test_runner_unknown_tool_is_rejected_outside_trace(runner):
    p = runner.execute("search_exploits", {"q": CVE})
    assert p["call_id"] is None and p["status"] == "invalid_request"
    assert runner.trace == [] and runner.rejected[0]["tool"] == "search_exploits"
    assert runner.execute("search_exploits", {})["status"] == "failed"


def test_runner_tool_exception_is_a_failed_call(runner, monkeypatch):
    monkeypatch.setattr(lookup_kev, "run", lambda args, s: 1 / 0)
    p = runner.execute("lookup_kev", {"cve_id": CVE})
    assert p["status"] == "failed" and "ZeroDivisionError" in p["error"]


def test_specs_match_contracts(runner):
    specs = {s["function"]["name"]: s["function"]["parameters"] for s in runner.specs()}
    assert set(specs) == {"environment_search", "lookup_vulnerability", "lookup_kev", "tavily_search"}
    assert specs["tavily_search"]["required"] == ["query", "allowed_domains", "max_results"]
    assert specs["environment_search"]["properties"]["query_type"]["enum"] == ["asset", "text", "flows", "business_service"]


# ---------------------------------------------------------------- live

@pytest.mark.live
def test_live_tools(env, tmp_path):
    r = ToolRunner(config.load_settings(), env, ENV_PATH, tmp_path)
    assert r.execute("lookup_vulnerability", {"cve_id": CVE})["status"] == "found"
    assert r.trace[0]["mode"] == "live"
    assert r.execute("lookup_kev", {"cve_id": CVE})["result"]["in_kev"] is False
    p = r.execute("tavily_search", {"query": f"{CVE} exploitability", "allowed_domains": ["msrc.microsoft.com"], "max_results": 3})
    assert p["status"] in ("found", "not_found") and r.trace[2]["receipts"][0]["request_id"]
    assert check_raw_outputs({"tool_trace": r.trace}) == []
