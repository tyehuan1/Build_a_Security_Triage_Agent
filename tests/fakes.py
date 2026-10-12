"""Test doubles for the network and the model."""

import json

from llm import LLMError, ModelReply, ToolCall, parse_json_reply


def reply(content="", tool_calls=()):
    """Build a ModelReply. tool_calls: [(name, arguments), ...]."""
    return ModelReply(content=content, tool_calls=[ToolCall(id=f"call_{i}", name=n, arguments=a)
                                                    for i, (n, a) in enumerate(tool_calls)])


class ScriptedLLM:
    """Stands in for OllamaClient: returns queued replies in order and records every request.

    Queue items: ModelReply (chat), dict (chat_json parsed result), str (chat_json raw content),
    or an Exception (raised, e.g. LLMError for an outage).
    """

    def __init__(self, *script):
        self.script = list(script)
        self.requests = []

    def _next(self, kind, messages, **kw):
        self.requests.append({"kind": kind, "messages": [dict(m) for m in messages], **kw})
        if not self.script:
            raise AssertionError(f"ScriptedLLM ran out of replies at request {len(self.requests)} ({kind})")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def chat(self, messages, *, tools=None, format=None, purpose=""):
        item = self._next("chat", messages, tools=tools, purpose=purpose)
        if not isinstance(item, ModelReply):
            raise AssertionError(f"expected a ModelReply for chat, got {type(item).__name__}")
        return item

    def chat_json(self, messages, schema, *, purpose=""):
        item = self._next("chat_json", messages, schema=schema, purpose=purpose)
        content = item if isinstance(item, str) else json.dumps(item)
        parsed, err = parse_json_reply(content, schema)  # same parsing and schema check as OllamaClient
        return ModelReply(content=content), parsed, err


__all__ = ["FakeResponse", "FakeNetwork", "ScriptedLLM", "reply", "LLMError"]


class FakeResponse:
    def __init__(self, status=200, body=None, url="https://example.test"):
        self.status_code = status
        self.url = url
        self.content = json.dumps(body if body is not None else {}).encode()
        self.text = self.content.decode()

    def json(self):
        return json.loads(self.content)


class FakeNetwork:
    """Returns queued outcomes in order, or routes by URL substring; records every call.

    outcomes: FakeResponse / Exception instances, consumed in order.
    routes:   {url_substring: FakeResponse} used when the queue is empty.
    """

    def __init__(self, *outcomes, routes=None):
        self.outcomes = list(outcomes)
        self.routes = routes or {}
        self.calls = []

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if self.outcomes:
            out = self.outcomes.pop(0)
        else:
            out = next((r for key, r in self.routes.items() if key in url), None)
            if out is None:
                raise AssertionError(f"unexpected network call: {method} {url}")
        if isinstance(out, Exception):
            raise out
        return out
