"""Source layer tests with a mocked network: retry, cache fallback, fault injection, receipts."""

import hashlib
import json

import pytest
import requests

import config
from fakes import FakeResponse
from sources import fetch_cve, fetch_kev, fetch_nvd, search_tavily

CVE = "CVE-2026-69730"


def cve_body(cve_id=CVE):
    return {"cveMetadata": {"cveId": cve_id}, "containers": {}}


TIMEOUT = requests.Timeout("read timed out")


# ---------------------------------------------------------------- retry and cache

def test_live_success_has_receipt(settings, net):
    fake = net(FakeResponse(200, cve_body(), url="https://cveawg.mitre.org/api/cve/" + CVE))
    r = fetch_cve(CVE, settings)
    assert (r.status, r.mode, r.attempts) == ("ok", "live", 1)
    assert r.receipt["http_status"] == 200
    assert r.receipt["sha256"] == hashlib.sha256(r.raw).hexdigest()
    assert len(fake.calls) == 1


def test_retry_then_success(settings, net):
    fake = net(TIMEOUT, FakeResponse(200, cve_body()))
    r = fetch_cve(CVE, settings)
    assert (r.status, r.mode, r.attempts) == ("ok", "live", 2)
    assert len(fake.calls) == 2


def test_two_failures_fall_back_to_cache(settings, net):
    net(TIMEOUT, FakeResponse(503, {"error": "down"}))
    r = fetch_cve(CVE, settings)
    manifest = json.loads(config.path(settings["paths"]["cache_manifest"]).read_text(encoding="utf-8"))
    meta = manifest["files"][settings["sources"]["cve"]["cache"]]
    assert (r.status, r.mode, r.attempts) == ("ok", "cached", 2)
    assert r.retrieved_at == meta["saved_at"]           # cached data is dated by when it was saved
    assert r.receipt["sha256"] == meta["sha256"]
    assert "HTTP 503" in r.fallback_reason
    assert r.data["cveMetadata"]["cveId"] == CVE


def test_two_failures_without_cache_fail(settings, net):
    settings["fault_injection"]["disable_cache"] = True
    net(TIMEOUT, TIMEOUT)
    r = fetch_cve(CVE, settings)
    assert (r.status, r.mode, r.data) == ("failed", None, None)
    assert "no cached fallback" in r.error


def test_404_is_not_found_without_retry_or_cache(settings, net):
    fake = net(FakeResponse(404, {"error": "CVE_RECORD_DNE"}))
    r = fetch_cve("CVE-2099-0001", settings)
    assert (r.status, r.mode) == ("not_found", "live")
    assert len(fake.calls) == 1


def test_client_error_is_not_retried_but_uses_cache(settings, net):
    fake = net(FakeResponse(403, {"error": "forbidden"}))
    r = fetch_nvd(CVE, settings)
    assert len(fake.calls) == 1
    assert (r.status, r.mode) == ("ok", "cached")


def test_cache_for_a_different_cve_is_not_used(settings, net):
    net(TIMEOUT, TIMEOUT)
    r = fetch_cve("CVE-2026-00001", settings)
    assert r.status == "failed"
    assert "does not cover this request" in r.error


def test_tampered_cache_is_rejected(settings, net, monkeypatch, tmp_path):
    manifest = json.loads(config.path(settings["paths"]["cache_manifest"]).read_text(encoding="utf-8"))
    manifest["files"][settings["sources"]["cve"]["cache"]]["sha256"] = "0" * 64
    fake_manifest = tmp_path / "manifest.json"
    fake_manifest.write_text(json.dumps(manifest))
    settings["paths"]["cache_manifest"] = str(fake_manifest)  # absolute path; config.path keeps it
    net(TIMEOUT, TIMEOUT)
    r = fetch_cve(CVE, settings)
    assert r.status == "failed"
    assert "SHA-256 does not match" in r.error


# ---------------------------------------------------------------- fault injection

def test_fault_injection_never_touches_the_network(settings, net):
    settings["fault_injection"]["kev"] = True
    fake = net()  # any network call would pop from an empty list and error
    r = fetch_kev(settings)
    assert fake.calls == []
    assert (r.status, r.mode, r.attempts) == ("ok", "cached", 2)
    assert "fault injection" in r.fallback_reason


def test_fault_injection_with_cache_disabled_fails(settings, net):
    settings["fault_injection"].update(cve=True, disable_cache=True)
    net()
    r = fetch_cve(CVE, settings)
    assert r.status == "failed" and "fault injection" in r.error


# ---------------------------------------------------------------- source-specific

def test_nvd_empty_result_is_not_found(settings, net):
    net(FakeResponse(200, {"totalResults": 0, "vulnerabilities": []}))
    assert fetch_nvd(CVE, settings).status == "not_found"


def test_tavily_has_no_cache(settings, net, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "test-key")
    net(TIMEOUT, TIMEOUT)
    r = search_tavily("q", ["cisa.gov"], 3, settings)
    assert (r.status, r.mode, r.attempts) == ("failed", None, 2)


def test_tavily_records_request_id_and_sends_domains(settings, net, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "test-key")
    fake = net(FakeResponse(200, {"results": [{"url": "https://cisa.gov/x"}], "request_id": "req-123"}))
    r = search_tavily("q", ["cisa.gov"], 3, settings)
    assert r.receipt["request_id"] == "req-123"
    body = fake.calls[0][2]["json"]
    assert body["include_domains"] == ["cisa.gov"] and body["max_results"] == 3
    assert fake.calls[0][2]["headers"]["Authorization"] == "Bearer test-key"


def test_tavily_empty_results_is_not_found(settings, net, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "test-key")
    net(FakeResponse(200, {"results": [], "request_id": "r"}))
    assert search_tavily("q", ["cisa.gov"], 3, settings).status == "not_found"


def test_tavily_missing_key_fails_cleanly(settings, net, monkeypatch):
    monkeypatch.setattr(config, "secret", lambda name: None)
    fake = net()
    r = search_tavily("q", ["cisa.gov"], 3, settings)
    assert r.status == "failed" and "TAVILY_API_KEY" in r.error and fake.calls == []


# ---------------------------------------------------------------- live smoke tests

@pytest.mark.live
def test_live_cve():
    r = fetch_cve(CVE, config.load_settings())
    assert (r.status, r.mode) == ("ok", "live") and r.receipt["http_status"] == 200


@pytest.mark.live
def test_live_nvd():
    r = fetch_nvd(CVE, config.load_settings())
    assert (r.status, r.mode) == ("ok", "live")


@pytest.mark.live
def test_live_kev():
    r = fetch_kev(config.load_settings())
    assert (r.status, r.mode) == ("ok", "live") and r.data["count"] > 1000


@pytest.mark.live
def test_live_tavily():
    r = search_tavily(f"{CVE} Windows DNS Server", ["msrc.microsoft.com", "nvd.nist.gov"], 3, config.load_settings())
    assert r.status == "ok" and r.receipt["request_id"]
