"""Model client tests: request shape, tool-call parsing, retry, transcript, fabricated-output detection."""

import json

import pytest
import requests

import config
import llm
from fakes import FakeNetwork, FakeResponse
from llm import LLMError, OllamaClient, detect_fabricated_tool_output
from tools.registry import tool_specs, validate_arguments

TOOLS = ["environment_search", "lookup_vulnerability", "lookup_kev", "tavily_search"]


@pytest.fixture
def post(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "test-key")
    monkeypatch.setattr(llm, "_sleep", lambda s: None)

    def install(*outcomes):
        fake = FakeNetwork(*outcomes)
        monkeypatch.setattr(llm, "_post", lambda url, **kw: fake("POST", url, **kw))
        return fake
    return install


def ollama_body(content="", tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls is not None:
        msg["tool_calls"] = tool_calls
    return {"model": "gemma4:31b", "message": msg, "done": True}


# ---------------------------------------------------------------- request and parsing

def test_request_shape_and_tool_call_parsing(settings, post, tmp_path):
    fake = post(FakeResponse(200, ollama_body(tool_calls=[
        {"id": "call_1", "function": {"name": "lookup_kev", "arguments": {"cve_id": "CVE-2026-69730"}}}])))
    client = OllamaClient(settings, tmp_path / "t.jsonl")
    r = client.chat([{"role": "user", "content": "hi"}], tools=tool_specs(settings), purpose="plan")
    body = fake.calls[0][2]["json"]
    assert body["options"]["temperature"] == 0 and body["stream"] is False and len(body["tools"]) == 4
    assert fake.calls[0][2]["headers"]["Authorization"] == "Bearer test-key"
    assert fake.calls[0][1] == "https://ollama.com/api/chat"
    assert [(c.id, c.name, c.arguments) for c in r.tool_calls] == [("call_1", "lookup_kev", {"cve_id": "CVE-2026-69730"})]
    assert r.assistant_message()["tool_calls"][0]["function"]["name"] == "lookup_kev"


def test_string_arguments_and_missing_id(settings, post):
    post(FakeResponse(200, ollama_body(tool_calls=[
        {"function": {"name": "lookup_kev", "arguments": '{"cve_id": "CVE-2026-69730"}'}},
        {"function": {"name": "lookup_kev", "arguments": "{not json"}}])))
    r = OllamaClient(settings).chat([], purpose="plan")
    assert r.tool_calls[0].arguments == {"cve_id": "CVE-2026-69730"} and r.tool_calls[0].id_generated
    assert r.tool_calls[1].arguments == "{not json"  # left raw for the runner to reject


SCHEMA = {"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]}


@pytest.mark.parametrize("content, parsed, error", [
    ('{"a": 1}', {"a": 1}, None),
    ('```json\n{"a": 2}\n```', {"a": 2}, None),
    ("ID: CVE-2026-69730", None, "not valid JSON"),
    ('{"a": "one"}', None, "does not match the schema"),
    ("[1, 2]", None, "not an object"),
])
def test_chat_json(settings, post, content, parsed, error):
    fake = post(FakeResponse(200, ollama_body(content=content)))
    _, got, err = OllamaClient(settings).chat_json([{"role": "user", "content": "x"}], SCHEMA)
    assert got == parsed
    assert (err is None) if error is None else (error in err)
    sent = fake.calls[0][2]["json"]
    assert sent["messages"][0]["role"] == "system" and '"required": ["a"]' in sent["messages"][0]["content"]
    assert sent["format"] == SCHEMA


# ---------------------------------------------------------------- failures

def test_retry_on_server_error(settings, post):
    fake = post(FakeResponse(503, {"error": "busy"}), FakeResponse(200, ollama_body(content="ok")))
    assert OllamaClient(settings).chat([]).content == "ok" and len(fake.calls) == 2


def test_auth_error_not_retried(settings, post, tmp_path):
    fake = post(FakeResponse(401, {"error": "unauthorized"}))
    client = OllamaClient(settings, tmp_path / "t.jsonl")
    with pytest.raises(LLMError, match="HTTP 401"):
        client.chat([], purpose="plan")
    assert len(fake.calls) == 1
    entry = json.loads((tmp_path / "t.jsonl").read_text().splitlines()[0])
    assert entry["response"] is None and "401" in entry["error"]


def test_network_down_raises_after_retry(settings, post):
    fake = post(requests.ConnectionError("down"), requests.Timeout("slow"))
    with pytest.raises(LLMError, match="2 attempt"):
        OllamaClient(settings).chat([])
    assert len(fake.calls) == 2


def test_missing_key(settings, monkeypatch):
    monkeypatch.setattr(config, "secret", lambda name: None)
    with pytest.raises(LLMError, match="OLLAMA_API_KEY"):
        OllamaClient(settings).chat([])


def test_transcript_has_no_secret(settings, post, tmp_path):
    post(FakeResponse(200, ollama_body(content="ok")))
    OllamaClient(settings, tmp_path / "t.jsonl").chat([{"role": "user", "content": "x"}], purpose="p")
    text = (tmp_path / "t.jsonl").read_text()
    assert "test-key" not in text and '"purpose": "p"' in text


# ---------------------------------------------------------------- fabricated tool output

@pytest.mark.parametrize("text", [
    'lookup_kev(cve_id="CVE-2026-69730") returned not in KEV',
    '{"name": "environment_search", "arguments": {"query_type": "asset", "query": "W01"}}',
    'Result: {"status": "not_found", "in_kev": false}',
    "<tool_call>lookup_vulnerability</tool_call>",
    "Tool result: CVSS 9.8, KEV not listed.",
    '{"call_id": "T9", "records": []}',
])
def test_detects_fabricated_tool_output(text):
    assert detect_fabricated_tool_output(text, TOOLS)


@pytest.mark.parametrize("text", [
    "Evidence gathering complete. T1 and T3 cover the asset and KEV status.",
    "I will look up the vulnerability record next.",
    "",
])
def test_allows_normal_text(text):
    assert detect_fabricated_tool_output(text, TOOLS) == []


# ---------------------------------------------------------------- live

@pytest.mark.live
def test_live_model_makes_a_real_tool_call(tmp_path):
    s = config.load_settings()
    client = OllamaClient(s, tmp_path / "t.jsonl")
    r = client.chat([{"role": "system", "content": "Use tools to gather evidence. Do not answer from memory."},
                     {"role": "user", "content": "Is CVE-2026-69730 in the CISA KEV catalog?"}],
                    tools=tool_specs(s), purpose="live-test")
    assert r.tool_calls, f"model answered without a tool call: {r.content[:200]}"
    call = r.tool_calls[0]
    assert call.name == "lookup_kev"
    validate_arguments(call.name, call.arguments, s)  # raises if the arguments break the contract
    assert detect_fabricated_tool_output(r.content, TOOLS) == []


@pytest.mark.live
def test_live_json_output_follows_schema(tmp_path):
    schema = {"type": "object", "properties": {"cve_id": {"type": "string"}, "severity": {"enum": ["Low", "Medium", "High", "Critical"]}},
              "required": ["cve_id", "severity"]}
    _, parsed, err = OllamaClient(config.load_settings()).chat_json(
        [{"role": "user", "content": "CVE-2026-69730 has CVSS 9.8. Return its ID and severity band."}], schema)
    assert err is None and parsed["cve_id"] == "CVE-2026-69730" and parsed["severity"] == "Critical"
