"""Tool registry and runner: the only path from a model tool request to a tool execution.

For each request the runner
  1. rejects unknown tool names and arguments that break the tool contract (one correction
     per tool, then status=failed - design "Tool execution" step);
  2. assigns the call ID (T1, T2, ...) - the model never creates call IDs;
  3. runs the tool and saves the raw output to <out_dir>/T#.json with its SHA-256;
  4. appends a tool_trace entry (output_schema.json) plus proof fields: model_call_id,
     started_at/finished_at, output_sha256 and source receipts;
  5. returns the contract result to the model, tagged with the call ID.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import jsonschema

import config
from tools import environment_search, lookup_kev, lookup_vulnerability, tavily_search
from tools.base import InvalidArguments, ToolOutput
from tools.tavily_search import domain_allowed
from sources.base import sha256

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"
ENV_MAX_RESULTS = 25


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def tool_specs(settings: dict) -> list[dict]:
    """Tool definitions sent to the model (Ollama / OpenAI function format)."""
    tav = settings["sources"]["tavily"]
    cve_param = {"type": "string", "pattern": CVE_PATTERN, "description": "CVE ID, e.g. CVE-2026-69730"}
    specs = {
        "environment_search": (
            "Search the Northbridge environment snapshot (simulated). query_type 'asset' matches an asset ID, name "
            "or tag (e.g. 'W01'); 'text' finds every record containing all query words (e.g. 'DNS Server') and "
            "reports which assets matched out of all assets; 'flows' returns permitted flows, denied paths and "
            "the zone for an asset ID plus perimeter policy and published services; 'business_service' returns "
            "business services by ID, name or supporting asset ID (RTO/RPO, consequence). Records carry locators, "
            "basis (stated/inferred) and unknown_fields. null means unknown, never safe.",
            {"query_type": {"type": "string", "enum": list(environment_search.QUERY_TYPES)},
             "query": {"type": "string", "minLength": 1},
             "max_results": {"type": "integer", "minimum": 1, "maximum": ENV_MAX_RESULTS}},
            ["query_type", "query"],
        ),
        "lookup_vulnerability": (
            "Retrieve the CVE record and the NVD record for a CVE and merge them: description, CWE, CVSS "
            "score/vector/metrics, affected products with fixed builds, CISA SSVC, and conflicts between sources.",
            {"cve_id": cve_param},
            ["cve_id"],
        ),
        "lookup_kev": (
            "Check whether a CVE is in the CISA Known Exploited Vulnerabilities catalog. "
            "Absence from KEV does not establish that a CVE is not exploited.",
            {"cve_id": cve_param},
            ["cve_id"],
        ),
        "tavily_search": (
            "Web search restricted to credible vendor, government and security-vendor domains. Use it to find "
            "in-the-wild exploitation reports, public proofs of concept, the vendor's exploitability assessment, "
            "and patch/KB or mitigation guidance. allowed_domains must be chosen from: "
            + ", ".join(tav["allowed_domains"]) + ".",
            {"query": {"type": "string", "minLength": 3},
             "allowed_domains": {"type": "array", "items": {"type": "string"}, "minItems": 1},
             "max_results": {"type": "integer", "minimum": 1, "maximum": tav["max_results_cap"]}},
            ["query", "allowed_domains", "max_results"],
        ),
    }
    return [{"type": "function", "function": {"name": name, "description": desc,
             "parameters": {"type": "object", "properties": props, "required": req, "additionalProperties": False}}}
            for name, (desc, props, req) in specs.items()]


def validate_arguments(name: str, args: dict, settings: dict) -> None:
    """Raise InvalidArguments when args break the tool contract."""
    spec = next(s["function"] for s in tool_specs(settings) if s["function"]["name"] == name)
    errors = sorted(jsonschema.Draft202012Validator(spec["parameters"]).iter_errors(args), key=lambda e: e.path)
    if errors:
        raise InvalidArguments("; ".join(f"{'/'.join(map(str, e.path)) or 'arguments'}: {e.message}" for e in errors))
    if name == "tavily_search":
        allow = settings["sources"]["tavily"]["allowed_domains"]
        bad = [d for d in args["allowed_domains"] if not domain_allowed(d, allow)]
        if bad:
            raise InvalidArguments(f"allowed_domains {bad} are not on the allowlist: {allow}")


class ToolRunner:
    def __init__(self, settings: dict, env: dict, env_path: str, out_dir: Path):
        self.settings = settings
        self.env = env
        self.env_path = env_path
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.trace: list[dict] = []
        self.rejected: list[dict] = []          # unknown tool names (cannot appear in tool_trace)
        self._invalid: dict[str, int] = {}      # invalid requests per tool name

    @property
    def names(self) -> list[str]:
        return [s["function"]["name"] for s in tool_specs(self.settings)]

    def specs(self) -> list[dict]:
        return tool_specs(self.settings)

    # ------------------------------------------------------------ execution

    def _run_tool(self, name: str, args: dict) -> ToolOutput:
        if name == "environment_search":
            return environment_search.run(args, self.env, self.env_path)
        module = {"lookup_vulnerability": lookup_vulnerability, "lookup_kev": lookup_kev, "tavily_search": tavily_search}[name]
        return module.run(args, self.settings)

    def _invalid_status(self, key: str) -> str:
        self._invalid[key] = self._invalid.get(key, 0) + 1
        return "invalid_request" if self._invalid[key] == 1 else "failed"

    def execute(self, name: str, arguments, *, selected_by: str = "model", model_call_id: Optional[str] = None) -> dict:
        """Run one requested tool call. Returns the message payload for the model."""
        started = _now()

        if name not in self.names:
            status = self._invalid_status(f"unknown:{name}")
            err = f"Unknown tool '{name}'. Allowed tools: {self.names}."
            self.rejected.append({"tool": name, "arguments": arguments, "model_call_id": model_call_id,
                                  "status": status, "error": err, "at": started})
            hint = " One correction is allowed." if status == "invalid_request" else " No further corrections allowed."
            return {"call_id": None, "tool": name, "status": status, "error": err + hint}

        call_id = f"T{len(self.trace) + 1}"
        args = arguments
        try:
            if isinstance(args, str):
                args = json.loads(args or "{}")
            if not isinstance(args, dict):
                raise InvalidArguments("arguments must be a JSON object")
            validate_arguments(name, args, self.settings)
        except (InvalidArguments, json.JSONDecodeError) as err:
            status = self._invalid_status(name)
            note = "Correct the arguments and call again (one correction allowed)." if status == "invalid_request" \
                else "Second invalid request for this tool: status=failed."
            out = ToolOutput({"status": status}, status, None, 1, False, "invalid arguments", f"{err}. {note}")
            return self._record(call_id, name, arguments if isinstance(arguments, dict) else {"_raw": arguments},
                                out, selected_by, model_call_id, started)

        try:
            out = self._run_tool(name, args)
        except Exception as err:  # unexpected tool bug: report as a failed call, never crash the run
            out = ToolOutput({"status": "failed"}, "failed", None, 1, False, "tool error", f"{type(err).__name__}: {err}")
        return self._record(call_id, name, args, out, selected_by, model_call_id, started)

    def _record(self, call_id, name, args, out: ToolOutput, selected_by, model_call_id, started) -> dict:
        finished = _now()
        raw = {"call_id": call_id, "tool": name, "selected_by": selected_by, "model_call_id": model_call_id,
               "arguments": args, "started_at": started, "finished_at": finished, "status": out.status,
               "error": out.error, "result": out.result, "receipts": out.receipts, "source_raw": out.source_raw}
        data = json.dumps(raw, indent=2, ensure_ascii=False).encode("utf-8")
        path = self.out_dir / f"{call_id}.json"
        path.write_bytes(data)
        try:
            rel = path.resolve().relative_to(config.ROOT).as_posix()
        except ValueError:
            rel = str(path.resolve())
        self.trace.append({
            "call_id": call_id,
            "tool": name,
            "selected_by": selected_by,
            "arguments": args,
            "result_status": out.status,
            "mode": out.mode,
            "attempts": out.attempts,
            "fallback_used": out.fallback_used,
            "result_summary": out.summary,
            "raw_output_path": rel,
            "evidence_ids": [],              # filled at assembly
            "error": out.error,
            "model_call_id": model_call_id,
            "started_at": started,
            "finished_at": finished,
            "output_sha256": sha256(data),
            "receipts": list(out.receipts),
        })
        return {"call_id": call_id, "tool": name, "status": out.status, "error": out.error, "result": out.result}


def load_raw_output(trace_entry: dict) -> dict:
    """Read a saved raw output (used by fact validation and the validator)."""
    p = Path(trace_entry["raw_output_path"])
    p = p if p.is_absolute() else config.ROOT / p
    return json.loads(p.read_text(encoding="utf-8"))
