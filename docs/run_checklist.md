# Complete-run demonstration checklist (Assignment 2 baseline)

**Run:** [`runs/baseline_assignment2/`](../runs/baseline_assignment2/) - generated 2026-10-11T22:00:42-04:00
**Code version:** git `86f90d3` (`uncommitted_changes: false`) | **Model:** Ollama Cloud `gemma4:31b`, temperature 0 | **Prompts:** `prompts-v1.1` | **Policy:** `rating-policy-v1.0`
**Reproduce:** `python run_assessment.py --run-id <name>` (live model and sources; results can vary run to run - see Limitations in the README)

## What the run folder preserves

| Item | File |
|---|---|
| Configuration (no secrets) | `config.json` |
| Every prompt and output schema used | `prompts.json` |
| Saved inputs with SHA-256 | `inputs.json`, `inputs/CVE-2026-69730.json`, `inputs/windows_enterprise_environment.json` |
| Raw tool outputs (one per call, hashed in the trace) | `tool_outputs/T1.json` ... `T7.json` |
| Every model request and reply, incl. structured tool calls | `model_transcript.jsonl` |
| Step-by-step run events | `run_log.jsonl` |
| Structured assessment + validation results | `assessment.json` |
| Citation review aid | `review_sheet.md` (from `python review.py ... --sheet-only`) |

## Checklist (assignment Step 2.2)

| # | Requirement | Result | Where it is shown |
|---|---|---|---|
| 1 | Intake loads the selected threat and the correct environment snapshot | Done | `run_log.jsonl` event `intake_ok` (CVE-2026-69730, W01, `northbridge-windows-enterprise-v1.0`); `inputs.json` SHA-256 `5b0b076c...` (CVE) and `78b6464f...` (environment) match `Resources/` |
| 2 | The model requests an allowed tool with valid arguments; code executes it and returns attributed evidence to the model | Done | `model_transcript.jsonl` turn `plan-1` holds 7 structured `tool_calls`. Each maps 1:1 to `tool_trace` T1-T7 by `model_call_id` (e.g. T1 = `call_51y1dt8s`). Validator checks *"Trace tool calls match structured tool calls in the model transcript"* and *"Raw tool outputs exist, match their SHA-256..."* pass. Each result went back to the model tagged with its call ID. |
| 3 | Environment lookup and at least one external evidence lookup execute and contribute | Done | Environment: T2 (asset W01), T3 (flows), T4 (business service), T5 (text "DNS Server"). External, all **live**: T1 CVE API + NVD API (HTTP 200), T6 CISA KEV feed, T7 Tavily (MSRC advisory). Contributions: C1/C2/C3 cite T1+T2; reachability cites T3; RTO cites T4; scope check cites T5; KEV and vendor rating cite T6/T7. |
| 4 | The agent compares prerequisites with environment facts, preserves unknowns, applies the policy, and gives a supported rating or insufficient-evidence status with an action | Done | C1 true, C2 true, C3 **unknown** (os_build null) -> **Insufficient Evidence (P-IE)**, provisional **High (P-H-L4I2)**. Unknown U1 (DC OS build) is decisive and listed in `missing_decisive_facts`. Fact validation passed on attempt 1 (every fact re-checked against the saved tool outputs). Validator *"Decision, scores, matrix and confidence match policy.py"* passes. Action: check the OS build on all four DCs, plus what each outcome would do to the decision. |
| 5 | A group member verifies the assessment and its cited evidence | **Pending** | Run `python review.py runs/baseline_assignment2/assessment.json`. Use `review_sheet.md`, which lists each evidence item next to the value at its locator in the saved tool output. |

**Anti-fabrication controls exercised in this run:** tool requests were accepted only from the API `tool_calls` field (no text replies were rejected in this run). Call IDs were assigned by code. Evidence provenance was filled from the trace, not the model. Facts were cross-checked against the raw outputs on disk. The trace-vs-transcript and SHA-256 checks pass. The rejection path is covered by `tests/test_orchestrator.py::test_fabricated_tool_output_is_rejected_and_never_becomes_evidence`.

## Baseline vs the group's expected assessment

Expected = `expected_assessment_output_CVE-2026-69730.json` (human version), with the machine version at `tests/fixtures/assessment_example_CVE-2026-69730_W01.json`.

| Field | Expected | Baseline (agent) | Match |
|---|---|---|---|
| Decision / rule | Insufficient Evidence / P-IE | Insufficient Evidence / P-IE | Yes |
| Provisional | High, P-H-L4I2 | High, P-H-L4I2 | Yes |
| C1 / C2 / C3 | true / true / unknown | true / true / unknown | Yes |
| Reachability / exploitability / exploit activity | 1 / 2 / 1 (likelihood 4, Medium) | 1 / 2 / 1 (likelihood 4, Medium) | Yes |
| KEV / in the wild / PoC / vendor likely | false / false / false / true | false / false / false / true | Yes |
| Criticality / blast radius (impact) | 2 / 2 (High) | 2 / 2 (High) | Yes |
| ADJ-RTO / ADJ-CIA | triggered, not binding / not triggered | triggered, not binding / not triggered | Yes |
| Technical severity | CVSS 3.1 9.8 Critical | CVSS 3.1 9.8 Critical (Microsoft CNA vector) | Yes |
| Scope check | Only W01 runs DNS Server | "only W01 ... among 44 assets searched" | Yes |
| Confidence | Low (design rule; human JSON said Medium, superseded) | Low | Yes |
| Fix | KB5122882, 10.0.20348.5622 | KB null, 10.0.20348.5622 | Partial - the model did not cite the KB page (the Tavily query did not target it) |
| Assumptions | A1 all DCs run DNS; A2 DNS not Internet-reachable | none recorded | Differs - the agent treated both as stated facts (cohort record; DNS listed as not published). This does not change the rating or confidence (already Low because of P-IE) |
| Priority | Urgent | High | Expected value retired (the "Urgent" option was removed by group decision) |
| Interim measures | Restrict port 53; monitor DNS/DC behaviour | Monitor DNS traffic on 53/tcp+udp | Partial |

**Conclusion:** the decision, policy rule, provisional rating, every scored factor and the confidence match the group's expected assessment. The differences are in supporting detail: the KB number, explicit assumptions, and the breadth of interim measures. The analyst should note these in the review.
