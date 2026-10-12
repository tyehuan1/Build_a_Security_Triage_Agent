"""Shared source access: HTTP with one retry, cached fallback, and a receipt for every result.

Every SourceResult carries a receipt proving where its bytes came from:
  live   -> HTTP status, final URL, byte count, SHA-256 of the body, elapsed time
  cached -> cache path, SHA-256 (checked against Resources/cache_manifest.json), saved_at
The tool layer saves the raw bytes and copies the receipt into the tool trace.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

import requests

import config

# Indirection so tests can replace the network and the clock.
_send: Callable[..., requests.Response] = requests.request
_sleep: Callable[[float], None] = time.sleep

NOT_RETRYABLE = {400, 401, 403, 404, 405, 422}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SimulatedOutage(ConnectionError):
    """Raised instead of a network call when fault injection is on for a source."""


@dataclass
class SourceResult:
    source: str                         # cve | nvd | kev | tavily
    status: str                         # ok | not_found | failed
    mode: Optional[str]                 # live | cached | None (failed)
    url: str                            # URL requested (or cache path)
    retrieved_at: str
    attempts: int
    data: Optional[object] = None       # parsed JSON
    raw: Optional[bytes] = None
    fallback_reason: Optional[str] = None
    error: Optional[str] = None
    receipt: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def cite_url(self) -> str:
        """The address the data actually came from: the URL fetched (live), the original source
        recorded in the cache manifest (cached), or the URL that was attempted (failed)."""
        if self.mode == "live":
            return self.receipt.get("final_url") or self.url
        if self.mode == "cached":
            return self.receipt.get("source_url") or self.url
        return self.url


def _load_cache(source: str, settings: dict, accept: Callable[[object], bool]) -> tuple[Optional[object], Optional[bytes], dict, Optional[str]]:
    """Return (data, raw, receipt, problem). problem is set when no usable cache exists."""
    if settings["fault_injection"].get("disable_cache"):
        return None, None, {}, "cache disabled by fault injection"
    rel = settings["sources"][source].get("cache")
    if not rel:
        return None, None, {}, "no cache configured for this source"
    p = config.path(rel)
    if not p.is_file():
        return None, None, {}, f"cache file {rel} not found"
    raw = p.read_bytes()
    manifest = json.loads(config.path(settings["paths"]["cache_manifest"]).read_text(encoding="utf-8"))
    meta = manifest["files"].get(rel)
    if not meta:
        return None, None, {}, f"{rel} is not listed in the cache manifest"
    digest = sha256(raw)
    if digest != meta["sha256"]:
        return None, None, {}, f"{rel} SHA-256 does not match the cache manifest"
    data = json.loads(raw.decode("utf-8"))
    if not accept(data):
        return None, None, {}, f"{rel} does not cover this request"
    receipt = {"cache_path": rel, "sha256": digest, "saved_at": meta["saved_at"], "bytes": len(raw),
               "source_url": meta.get("source_url")}
    return data, raw, receipt, None


def fetch(
    source: str,
    url: str,
    settings: dict,
    *,
    method: str = "GET",
    headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    cache_accepts: Optional[Callable[[object], bool]] = None,
) -> SourceResult:
    """Fetch JSON from a source: up to `retry.attempts` tries, then the cached copy if one fits.

    404 is a definitive answer (not_found) and does not fall back to cache.
    cache_accepts(data) -> bool decides whether the cached file covers this request;
    pass None for sources that have no cache (Tavily).
    """
    r = settings["retry"]
    max_attempts = r["attempts"]
    attempts, last_error = 0, None

    for attempt in range(1, max_attempts + 1):
        attempts = attempt
        started = time.monotonic()
        try:
            if settings["fault_injection"].get(source):
                raise SimulatedOutage(f"{source} unavailable (fault injection)")
            resp = _send(method, url, headers=headers, json=json_body, timeout=r["http_timeout_s"])
            elapsed_ms = int((time.monotonic() - started) * 1000)
            receipt = {
                "http_status": resp.status_code,
                "final_url": resp.url,
                "bytes": len(resp.content),
                "sha256": sha256(resp.content),
                "elapsed_ms": elapsed_ms,
            }
            if resp.status_code == 404:
                return SourceResult(source, "not_found", "live", url, now_iso(), attempts, raw=resp.content, receipt=receipt)
            if resp.status_code >= 400:
                last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                if resp.status_code in NOT_RETRYABLE:
                    break
            else:
                data = resp.json()
                return SourceResult(source, "ok", "live", url, now_iso(), attempts, data=data, raw=resp.content, receipt=receipt)
        except (requests.RequestException, ValueError, SimulatedOutage) as err:
            last_error = f"{type(err).__name__}: {err}"
        if attempt < max_attempts:
            _sleep(r["backoff_s"])

    if cache_accepts is not None:
        data, raw, receipt, problem = _load_cache(source, settings, cache_accepts)
        if problem is None:
            return SourceResult(
                source, "ok", "cached", receipt["cache_path"], receipt["saved_at"], attempts,
                data=data, raw=raw, receipt=receipt,
                fallback_reason=f"live request failed after {attempts} attempt(s) ({last_error}); used cached copy saved {receipt['saved_at']}",
            )
        last_error = f"{last_error}; no cached fallback: {problem}"
    return SourceResult(source, "failed", None, url, now_iso(), attempts, error=last_error)
