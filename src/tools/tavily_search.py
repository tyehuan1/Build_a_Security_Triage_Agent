"""tavily_search: model-constructed web search restricted to credible domains.

Contract (design doc):
  in : {"query": str, "allowed_domains": [str], "max_results": int}
  out: {status: found|not_found|failed, results[{title, url, snippet, published_date}], retrieved_at, mode: "live"}
Role: second check on exploit activity (credible in-the-wild report -> 2; credible PoC or vendor
"exploitation likely" -> 1) and guidance for recommended actions. The model chooses whether to
search and what to search for. On failure: status=failed (no cache).
"""

from __future__ import annotations

from urllib.parse import urlparse

from sources import search_tavily
from tools.base import ToolOutput, receipt_of

SNIPPET_CHARS = 1200  # Tavily content is ~1,300 chars; MSRC's exploitability table sits near char 300


def domain_allowed(host: str, allowlist: list[str]) -> bool:
    host = host.lower().split(":")[0]
    return any(host == d or host.endswith("." + d) for d in allowlist)


def run(args: dict, settings: dict) -> ToolOutput:
    allowlist = settings["sources"]["tavily"]["allowed_domains"]
    res = search_tavily(args["query"], args["allowed_domains"], args["max_results"], settings)
    receipts = [receipt_of(res)]
    base = {"query": args["query"], "allowed_domains": args["allowed_domains"], "retrieved_at": res.retrieved_at, "mode": "live"}

    if res.status == "failed":
        return ToolOutput({"status": "failed", "results": [], **base, "mode": None}, "failed", None, max(res.attempts, 1),
                          False, f"Tavily search failed: {res.error}", res.error, receipts)

    results, dropped = [], 0
    for r in (res.data or {}).get("results", []):
        if not domain_allowed(urlparse(r.get("url", "")).netloc, allowlist):
            dropped += 1  # defence in depth: Tavily should already have filtered these
            continue
        results.append({"title": r.get("title"), "url": r.get("url"), "snippet": (r.get("content") or "")[:SNIPPET_CHARS],
                        "published_date": r.get("published_date"), "score": r.get("score")})
    status = "found" if results else "not_found"
    result = {"status": status, "results": results, **base, "request_id": res.receipt.get("request_id"),
              "dropped_off_allowlist": dropped}
    summary = f"{len(results)} result(s) for '{args['query']}'" + (f"; {dropped} dropped (off allowlist)" if dropped else "")
    return ToolOutput(result, status, "live", max(res.attempts, 1), False, summary, None, receipts, source_raw={"tavily": res.data})
