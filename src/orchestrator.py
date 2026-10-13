"""Orchestration: the design's workflow table, one function per step.

  Intake (code) -> Plan + follow-up loop (model, tools) -> Evidence completeness (code)
  -> Extract facts (model) -> Fact validation (code) -> Gate 1 / Gate 2 (code, policy.py)
  -> Explain and recommend (model) -> Assemble, validate and save (code) -> Analyst review (human, review.py)

Everything a run uses or produces is saved under model_outputs_and_assessments/<run_id>/:
    assessment.json             the structured assessment (with validation results)
    tool_outputs/T#.json        raw tool outputs, SHA-256 recorded in the tool trace
    inputs/                     copies of the threat input and environment snapshot
    other_info/                 config.json, inputs.json (hashes), prompts.json, model_transcript.jsonl, run_log.jsonl
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import config
import prompts
from assemble import build_assessment, fallback_explanation
from factcheck import validate_facts
from llm import LLMError, OllamaClient, detect_fabricated_tool_output
from policy import PolicyInputs, evaluate, parse_cvss_vector
from tools.registry import ToolRunner, load_raw_output
from validate import validate_assessment

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
REQUIRED_TOOLS = ("environment_search", "lookup_vulnerability")
SUCCESS = ("found", "not_found")
TOOL_MESSAGE_CHARS = 20000


class StopRun(Exception):
    """A step that, per the design, ends the run with Review Needed before an assessment can be built."""

    def __init__(self, stage: str, reason: str):
        super().__init__(f"{stage}: {reason}")
        self.stage, self.reason = stage, reason


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(config.ROOT).as_posix()
    except ValueError:
        return str(p.resolve())


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _code_version() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=config.ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "src", "config"], cwd=config.ROOT,
                                    capture_output=True, text=True, timeout=10).stdout.strip())
        return {"git_commit": commit or None, "uncommitted_changes": dirty}
    except (OSError, subprocess.SubprocessError):
        return {"git_commit": None, "uncommitted_changes": None}


class RunLog:
    def __init__(self, path: Path):
        self.path = path

    def __call__(self, event: str, **data) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"at": _now(), "event": event, **data}, ensure_ascii=False, default=str) + "\n")


# ---------------------------------------------------------------- step 1: intake

def intake(settings: dict, run_dir: Path) -> tuple[dict, dict]:
    """Validate the CVE ID and the environment snapshot; save input copies. Raises StopRun (P-RV-F)."""
    inp = settings["inputs"]
    if not CVE_RE.match(inp["cve_id"] or ""):
        raise StopRun("intake", f"malformed CVE ID {inp['cve_id']!r}")
    env_path = config.path(inp["environment_snapshot"]["path"])
    threat_path = config.path(inp["threat_input"]["path"])
    if not env_path.is_file():
        raise StopRun("intake", f"environment snapshot {inp['environment_snapshot']['path']} not found")
    try:
        env = json.loads(env_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise StopRun("intake", f"environment snapshot is not parseable JSON: {err}")
    if not isinstance(env, dict) or not isinstance(env.get("assets"), list):
        raise StopRun("intake", "environment snapshot has no assets list")
    if inp["asset_id"] not in {a.get("asset_id") for a in env["assets"]}:
        raise StopRun("intake", f"asset {inp['asset_id']} is not in the environment snapshot")
    if not threat_path.is_file():
        raise StopRun("intake", f"saved threat input {inp['threat_input']['path']} not found")

    inputs_dir = run_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    saved = {}
    for label, p in (("threat_input", threat_path), ("environment_snapshot", env_path)):
        shutil.copy2(p, inputs_dir / p.name)
        saved[label] = {"source_path": _rel(p), "copy": _rel(inputs_dir / p.name), "sha256": _sha(p)}
    (run_dir / "other_info" / "inputs.json").write_text(json.dumps(saved, indent=2), encoding="utf-8")

    facts = {
        "risk_question": inp["risk_question"], "cve_id": inp["cve_id"], "asset_id": inp["asset_id"],
        "threat_input_path": inp["threat_input"]["path"], "environment_id": inp["environment_snapshot"]["id"],
        "environment_data_type": inp["environment_snapshot"]["data_type"], "environment_path": inp["environment_snapshot"]["path"],
        "run_date": datetime.now().astimezone().date().isoformat(),
    }
    return facts, env


# ---------------------------------------------------------------- steps 2-4: plan, execute, follow up

def _tool_message(name: str, payload: dict) -> dict:
    content = json.dumps(payload, ensure_ascii=False)
    if len(content) > TOOL_MESSAGE_CHARS:
        content = content[:TOOL_MESSAGE_CHARS] + f' ... [truncated; full result saved as {payload.get("call_id")}]'
    return {"role": "tool", "tool_name": name, "content": content}


class Planner:
    """Runs the model's tool-calling conversation. The model chooses tools and queries; code executes them."""

    def __init__(self, llm, runner: ToolRunner, settings: dict, log: RunLog):
        self.llm, self.runner, self.settings, self.log = llm, runner, settings, log
        self.rounds = 0
        self.fabrications: list[dict] = []
        self.budget_refused: list[str] = []

    def _execute(self, reply) -> None:
        for tc in reply.tool_calls:
            if len(self.runner.trace) >= self.settings["model"]["max_tool_calls"]:
                self.budget_refused.append(tc.id)
                payload = {"call_id": None, "tool": tc.name, "status": "failed",
                           "error": "Tool-call budget exhausted; not executed."}
                self.log("tool_budget_refused", tool=tc.name, model_call_id=tc.id)
            else:
                payload = self.runner.execute(tc.name, tc.arguments, model_call_id=tc.id)
                self.log("tool_call", call_id=payload["call_id"], tool=tc.name, arguments=tc.arguments,
                         status=payload["status"], model_call_id=tc.id)
            self.messages.append(_tool_message(tc.name, payload))

    def _turn(self, purpose: str) -> Optional[str]:
        """One model turn. Returns 'tools', 'complete', 'rejected' or 'text'."""
        reply = self.llm.chat(self.messages, tools=self.runner.specs(), purpose=purpose)
        self.messages.append(reply.assistant_message())
        if reply.tool_calls:
            self._execute(reply)
            return "tools"
        reasons = detect_fabricated_tool_output(reply.content, self.runner.names)
        if reasons:
            self.fabrications.append({"turn": purpose, "reasons": reasons, "content": reply.content[:500]})
            self.log("fabricated_tool_output_rejected", turn=purpose, reasons=reasons)
            self.messages.append({"role": "user", "content": prompts.FABRICATION_REJECTED.format(
                reasons="; ".join(reasons), complete=prompts.COMPLETE_SIGNAL)})
            return "rejected"
        if prompts.COMPLETE_SIGNAL in reply.content.upper():
            self.log("model_signalled_complete", turn=purpose, summary=reply.content[:1500])
            return "complete"
        self.messages.append({"role": "user", "content": f'Request tools through the tool-calling interface, or reply with '
                                                         f'"{prompts.COMPLETE_SIGNAL}" if evidence gathering is finished.'})
        return "text"

    def gather(self, intake_facts: dict) -> None:
        max_rounds = self.settings["model"]["max_tool_rounds"]
        self.messages = [{"role": "system", "content": prompts.plan_system(max_rounds)},
                         {"role": "user", "content": prompts.plan_user(intake_facts)}]
        while self.rounds < max_rounds:
            self.rounds += 1
            if self._turn(f"plan-{self.rounds}") == "complete":
                return
        self.log("round_cap_reached", rounds=self.rounds)

    def missing_required(self) -> list[str]:
        done = {t["tool"] for t in self.runner.trace if t["result_status"] in SUCCESS}
        return [t for t in REQUIRED_TOOLS if t not in done]

    def completeness_followup(self, missing: list[str]) -> None:
        """Design: one loop back to the model when required lookups are missing."""
        self.log("evidence_incomplete", missing=missing)
        self.messages.append({"role": "user", "content": prompts.MISSING_REQUIRED_EVIDENCE.format(
            missing=", ".join(missing), complete=prompts.COMPLETE_SIGNAL)})
        for i in range(2):  # the follow-up tool turn, then its completion reply
            if self._turn(f"completeness-{i + 1}") != "tools":
                break


# ---------------------------------------------------------------- steps 5-6: extract and validate facts

def successful_results(trace: list[dict]) -> list[dict]:
    return [{"call_id": t["call_id"], "tool": t["tool"], "arguments": t["arguments"], "result": load_raw_output(t)["result"]}
            for t in trace if t["result_status"] in SUCCESS]


def extract_and_validate(llm, trace, intake_facts, settings, log) -> tuple[dict, dict]:
    """Returns (facts, fact_validation record). Raises StopRun if no usable JSON is produced."""
    messages = [{"role": "system", "content": prompts.EXTRACT_SYSTEM},
                {"role": "user", "content": prompts.extract_user(intake_facts, successful_results(trace))}]
    attempts, problems, facts = [], [], None
    for attempt in (1, 2):
        reply, parsed, err = llm.chat_json(messages, prompts.EXTRACTION_SCHEMA, purpose=f"extract-{attempt}")
        problems = [err] if err else validate_facts(parsed, trace, intake_facts, settings)
        if parsed is not None and not err:
            facts = parsed
        attempts.append({"attempt": attempt, "passed": not problems, "problems": problems})
        log("fact_validation", attempt=attempt, passed=not problems, problems=problems)
        if not problems:
            break
        messages += [{"role": "assistant", "content": reply.content},
                     {"role": "user", "content": prompts.FACT_VALIDATION_FAILED.format(problems="\n".join(f"- {p}" for p in problems))}]
    if facts is None:
        raise StopRun("extract", f"no schema-valid fact extraction after 2 attempts: {problems}")
    return facts, {"passed": not problems, "attempts": attempts}


# ---------------------------------------------------------------- step 7: policy

def policy_inputs(facts: dict, trace: list[dict], fact_validation: dict, completeness: dict) -> PolicyInputs:
    f = facts
    vector = f["technical_severity"].get("vector")
    ea = f["likelihood"]["exploit_activity"]
    return PolicyInputs(
        conditions={c["id"]: c["result"] for c in f["conditions"]},
        decisive_tool_failure=bool(completeness["missing"]),
        fact_validation_failed=not fact_validation["passed"],
        any_tool_failed=any(t["result_status"] == "failed" for t in trace),
        assumptions_used=bool(f["assumptions"]),
        reachability=f["likelihood"]["reachability"]["value"],
        cvss_metrics=parse_cvss_vector(vector) if vector else None,
        kev_listed=ea["kev_listed"], credible_in_the_wild=ea["credible_in_the_wild"],
        public_poc=ea["public_poc"], vendor_exploitation_likely=ea["vendor_exploitation_likely"],
        asset_criticality=f["impact"]["asset_criticality"]["value"], blast_radius=f["impact"]["blast_radius"]["value"],
        rto_hours=f["impact"]["rto_hours"]["value"],
    )


# ---------------------------------------------------------------- step 8: explain

def explain(llm, intake_facts, policy_result, facts, log) -> tuple[dict, str]:
    decision_view = {k: policy_result[k] for k in ("decision", "applicability", "gate_2_status", "likelihood", "impact",
                                                   "matrix_result", "confidence")}
    messages = [{"role": "system", "content": prompts.EXPLAIN_SYSTEM},
                {"role": "user", "content": prompts.explain_user(intake_facts, decision_view, facts)}]
    err = None
    for attempt in (1, 2):
        try:
            reply, parsed, err = llm.chat_json(messages, prompts.EXPLANATION_SCHEMA, purpose=f"explain-{attempt}")
        except LLMError as e:
            err = str(e)
            break
        if parsed:
            return parsed, "model"
        messages += [{"role": "assistant", "content": reply.content},
                     {"role": "user", "content": f"Your reply was rejected: {err}. Return the complete JSON object."}]
    log("explanation_failed", error=err)
    return fallback_explanation(policy_result, err), f"fallback ({err})"


# ---------------------------------------------------------------- the run

def run_assessment(settings: dict, *, llm_factory: Optional[Callable] = None, runs_dir: Optional[Path] = None,
                   run_id: Optional[str] = None) -> dict:
    """Run the full workflow. Returns {"status", "run_dir", "assessment_path" | "failure_path", ...}."""
    run_id = run_id or f"{datetime.now():%Y%m%d-%H%M%S}_{settings['inputs']['cve_id']}_{settings['inputs']['asset_id']}"
    run_dir = Path(runs_dir or config.path(settings["paths"]["runs_dir"])) / run_id
    # A pre-created placeholder folder (empty apart from .gitkeep) may be used; never overwrite a previous run.
    if run_dir.exists() and any(p.name != ".gitkeep" for p in run_dir.iterdir()):
        raise FileExistsError(f"{run_dir} already contains a run; choose another --run-id")
    info = run_dir / "other_info"
    info.mkdir(parents=True, exist_ok=True)
    (run_dir / ".gitkeep").unlink(missing_ok=True)
    log = RunLog(info / "run_log.jsonl")
    (info / "config.json").write_text(json.dumps(config.redacted(settings), indent=2), encoding="utf-8")
    (info / "prompts.json").write_text(json.dumps(prompts.prompt_bundle(settings["model"]["max_tool_rounds"]), indent=2),
                                       encoding="utf-8")
    transcript = info / "model_transcript.jsonl"
    llm = (llm_factory or (lambda path: OllamaClient(settings, path)))(transcript)
    log("run_started", run_id=run_id, model=settings["model"]["name"],
        fault_injection={k: v for k, v in settings["fault_injection"].items() if not k.startswith("$")})

    stage = "intake"
    planner = None
    try:
        intake_facts, env = intake(settings, run_dir)
        log("intake_ok", **{k: intake_facts[k] for k in ("cve_id", "asset_id", "environment_id")})

        stage = "plan"
        runner = ToolRunner(settings, env, settings["inputs"]["environment_snapshot"]["path"], run_dir / "tool_outputs")
        planner = Planner(llm, runner, settings, log)
        planner.gather(intake_facts)

        stage = "completeness"
        missing = planner.missing_required()
        followed_up = bool(missing)
        if missing:
            planner.completeness_followup(missing)
            missing = planner.missing_required()
        completeness = {"required": list(REQUIRED_TOOLS), "followed_up": followed_up, "missing": missing}
        log("evidence_completeness", **completeness)
        if not runner.trace:
            raise StopRun("completeness", "the model made no tool calls")

        stage = "extract"
        facts, fact_validation = extract_and_validate(llm, runner.trace, intake_facts, settings, log)

        stage = "policy"
        policy_result = evaluate(policy_inputs(facts, runner.trace, fact_validation, completeness))
        log("policy_result", decision=policy_result["decision"], confidence=policy_result["confidence"])

        stage = "explain"
        explanation, explanation_status = explain(llm, intake_facts, policy_result, facts, log)

        stage = "assemble"
        run = {"run_id": run_id, "run_dir": _rel(run_dir), "prompt_version": prompts.PROMPT_VERSION,
               "code_version": _code_version(), "transcript_path": _rel(transcript), "plan_rounds": planner.rounds,
               "fabrication_rejections": planner.fabrications, "rejected_tool_requests": runner.rejected,
               "budget_refused_calls": planner.budget_refused,
               "completeness": completeness, "fact_validation": fact_validation, "explanation_status": explanation_status}
        assessment = build_assessment(run=run, intake=intake_facts, settings=settings, facts=facts,
                                      policy_result=policy_result, explanation=explanation, trace=runner.trace)
        schema = json.loads(config.path(settings["paths"]["schema"]).read_text(encoding="utf-8"))
        assessment["validation"] = validate_assessment(assessment, schema)
        passed = assessment["validation"]["schema_valid"] and all(c["passed"] for c in assessment["validation"]["checks"])
        out = run_dir / "assessment.json"
        out.write_text(json.dumps(assessment, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        log("assessment_saved", path=_rel(out), validation_passed=passed)
        return {"status": "completed" if passed else "completed_invalid", "run_dir": run_dir, "assessment_path": out,
                "assessment": assessment, "validation_passed": passed}

    except (StopRun, LLMError) as err:
        reason = err.reason if isinstance(err, StopRun) else str(err)
        stage = err.stage if isinstance(err, StopRun) else stage
        failure = {"run_id": run_id, "status": "stopped", "stage": stage, "rating": "Review Needed",
                   "policy_rule_applied": "P-RV-F", "reason": reason, "at": _now(),
                   "tool_trace": planner.runner.trace if planner else [],
                   "note": "Run stopped before an assessment could be assembled (design: intake failure or unrecoverable "
                           "step). Analyst review required."}
        out = run_dir / "run_failure.json"
        out.write_text(json.dumps(failure, indent=2, ensure_ascii=False), encoding="utf-8")
        log("run_stopped", stage=stage, reason=reason)
        return {"status": "stopped", "stage": stage, "reason": reason, "run_dir": run_dir, "failure_path": out}
