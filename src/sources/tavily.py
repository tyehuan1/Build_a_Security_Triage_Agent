"""Tavily web search. Live only: the design gives tavily_search no cached fallback."""

import config
from sources.base import SourceResult, fetch, now_iso


def search_tavily(query: str, include_domains: list[str], max_results: int, settings: dict) -> SourceResult:
    url = settings["sources"]["tavily"]["url"]
    key = config.secret("TAVILY_API_KEY")
    if not key:
        return SourceResult("tavily", "failed", None, url, now_iso(), 0, error="TAVILY_API_KEY is not set in .env")
    body = {"query": query, "include_domains": include_domains, "max_results": max_results, "search_depth": "basic"}
    res = fetch("tavily", url, settings, method="POST", headers={"Authorization": f"Bearer {key}"}, json_body=body)
    if res.ok:
        res.receipt["request_id"] = res.data.get("request_id")
        if not res.data.get("results"):
            res.status = "not_found"
    return res
