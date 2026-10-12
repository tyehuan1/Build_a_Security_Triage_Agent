"""Model client: Ollama Cloud /api/chat with native tool calling and JSON-schema output.

Model settings (provider, model name, temperature, timeouts) come from config/settings.json.
Every request and reply is appended to the run's model_transcript.jsonl so the run record shows
exactly which tool calls the model asked for.

Tool requests are only ever taken from the API's structured message.tool_calls field.
detect_fabricated_tool_output() flags reply text that imitates a tool call or tool result, so
the orchestrator can reject it instead of treating it as evidence.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import jsonschema
import requests

import config

# Indirection so tests can replace the network and the clock.
_post: Callable[..., requests.Response] = requests.post
_sleep: Callable[[float], None] = time.sleep

NOT_RETRYABLE = {400, 401, 403, 404, 422}


class LLMError(RuntimeError):
    """The model service could not produce a reply (after retry)."""


@dataclass
class ToolCall:
    id: str                       # model/API call ID (generated when the API omits one)
    name: str
    arguments: object             # dict normally; raw string if the model sent unparseable JSON
    id_generated: bool = False


@dataclass
class ModelReply:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    thinking: Optional[str] = None
    raw: dict = field(default_factory=dict)
    index: int = 0                # position in the transcript
    latency_ms: int = 0

    def assistant_message(self) -> dict:
        """The reply as a chat message to append to the conversation."""
        msg = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = [{"id": c.id, "function": {"name": c.name, "arguments": c.arguments}} for c in self.tool_calls]
        return msg


# ---------------------------------------------------------------- fabricated tool output

def detect_fabricated_tool_output(content: str, tool_names: list[str]) -> list[str]:
    """Reasons why reply text looks like a tool call or tool result written as prose.

    Referring to a real call ID ("T1 shows ...") is allowed; imitating the call or its output is not.
    """
    if not content:
        return []
    names = "|".join(map(re.escape, tool_names))
    patterns = [
        (rf"\b({names})\s*\(", "writes a tool invocation as text"),
        (rf'"name"\s*:\s*"({names})"', "writes a tool call as JSON text"),
        (r'"(status|result_status)"\s*:\s*"(found|not_found|failed|invalid_request)"', "contains a tool-result status field"),
        (r'"(call_id|in_kev|records|tool_calls|retrieved_at)"\s*:', "contains tool-result JSON keys"),
        (r"<\|?\s*tool_?(call|response|result|output)", "contains tool-call markup"),
        (r"(?i)\btool\s+(result|output|response)\s*[:=]", "claims to show a tool result"),
    ]
    return [reason for pat, reason in patterns if re.search(pat, content)]


# ---------------------------------------------------------------- client

def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class OllamaClient:
    def __init__(self, settings: dict, transcript_path: Optional[Path] = None):
        self.settings = settings
        self.model = settings["model"]
        self.transcript_path = Path(transcript_path) if transcript_path else None
        self.calls = 0

    @property
    def url(self) -> str:
        return self.model["base_url"].rstrip("/") + "/api/chat"

    def _log(self, entry: dict) -> None:
        if self.transcript_path:
            self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
            with self.transcript_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def chat(self, messages: list[dict], *, tools: Optional[list[dict]] = None, format: Optional[dict] = None,
             purpose: str = "") -> ModelReply:
        key = config.secret("OLLAMA_API_KEY")
        if not key:
            raise LLMError("OLLAMA_API_KEY is not set in .env")
        body = {"model": self.model["name"], "messages": messages, "stream": False,
                "options": {"temperature": self.model["temperature"]}}
        if tools:
            body["tools"] = tools
        if format:
            body["format"] = format

        self.calls += 1
        index = self.calls
        attempts, last_error, data, started = 0, None, None, time.monotonic()
        for attempt in range(1, self.settings["retry"]["attempts"] + 1):
            attempts = attempt
            try:
                resp = _post(self.url, headers={"Authorization": f"Bearer {key}"}, json=body, timeout=self.model["timeout_s"])
                if resp.status_code < 400:
                    data = resp.json()
                    if data.get("error"):
                        last_error = f"model error: {data['error']}"
                        data = None
                    else:
                        break
                else:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    if resp.status_code in NOT_RETRYABLE:
                        break
            except (requests.RequestException, ValueError) as err:
                last_error = f"{type(err).__name__}: {err}"
            if attempt < self.settings["retry"]["attempts"]:
                _sleep(self.settings["retry"]["backoff_s"])
        latency_ms = int((time.monotonic() - started) * 1000)

        request_log = {"model": body["model"], "options": body["options"], "messages": messages,
                       "tools": [t["function"]["name"] for t in tools or []], "format": format}
        if data is None:
            self._log({"index": index, "purpose": purpose, "at": _now(), "attempts": attempts, "latency_ms": latency_ms,
                       "request": request_log, "response": None, "error": last_error})
            raise LLMError(f"model call '{purpose}' failed after {attempts} attempt(s): {last_error}")

        reply = self._parse(data, index, latency_ms)
        self._log({"index": index, "purpose": purpose, "at": _now(), "attempts": attempts, "latency_ms": latency_ms,
                   "request": request_log, "response": data, "error": None,
                   "parsed_tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments, "id_generated": c.id_generated}
                                         for c in reply.tool_calls]})
        return reply

    def _parse(self, data: dict, index: int, latency_ms: int) -> ModelReply:
        msg = data.get("message") or {}
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args.strip() else {}
                except json.JSONDecodeError:
                    pass  # keep the raw string; the tool runner reports it as an invalid request
            cid = tc.get("id")
            calls.append(ToolCall(id=cid or f"gen_{index}_{i}", name=fn.get("name", ""), arguments=args, id_generated=not cid))
        return ModelReply(content=msg.get("content") or "", tool_calls=calls, thinking=msg.get("thinking"),
                          raw=data, index=index, latency_ms=latency_ms)

    def chat_json(self, messages: list[dict], schema: dict, *, purpose: str = "") -> tuple[ModelReply, Optional[dict], Optional[str]]:
        """Structured-output call. Returns (reply, parsed JSON or None, error or None).

        Ollama Cloud ignores `format` for gemma4:31b (checked 2026-10-11), so the schema is also
        given as a system instruction, and the reply is validated against the schema here.
        """
        reply = self.chat([json_instruction(schema), *messages], format=schema, purpose=purpose)
        parsed, err = parse_json_reply(reply.content, schema)
        return reply, parsed, err


def json_instruction(schema: dict) -> dict:
    return {"role": "system", "content": "Respond with a single JSON object only: no prose, no code fences. "
                                         "It must validate against this JSON Schema:\n" + json.dumps(schema)}


def parse_json_reply(content: str, schema: dict) -> tuple[Optional[dict], Optional[str]]:
    """Parse a JSON-object reply (tolerating code fences) and validate it against schema."""
    text = (content or "").strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.S)
    if fenced:
        text = fenced.group(1)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as err:
        return None, f"reply is not valid JSON: {err}"
    if not isinstance(parsed, dict):
        return None, "reply JSON is not an object"
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(parsed), key=lambda e: list(e.path))
    if errors:
        return None, "reply does not match the schema: " + "; ".join(
            f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in errors[:10])
    return parsed, None
