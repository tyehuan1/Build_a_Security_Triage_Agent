# Security Triage Agent - CVE-2026-69730 on Northbridge Services

Project Objective: Design and build an agentic system that assesses a specific threat or weakness in an infrastructure and assigns an evidence-supported High, Medium, or Low risk rating. Explain the affected or potentially affected assets, rating rationale, uncertainty, and recommended action.

The agent assesses **CVE-2026-69730** (unauthenticated remote code execution in the Windows DNS Server service) against the **Northbridge Services** simulated Windows enterprise environment, focusing on the **W01 domain controllers**. An LLM (Ollama Cloud `gemma4:31b`) decides which tools to call and with what arguments. Code runs every tool, checks every fact the model extracts against the saved tool output, and applies the group's applicability-and-impact rating policy deterministically. The result is a High / Medium / Low rating, or an explicit Insufficient Evidence / Review Needed status, with cited evidence, unknowns, confidence and a recommended action.

## Repository layout

| Path | Contents |
|---|---|
| `Project_Design.docx` | Step 1 design: risk question, rating policy, workflow table, tool contracts, failure handling, acceptance test |
| `run_assessment.py` | Runs the complete workflow (command-line entry point) |
| `review.py` | Analyst review: writes a citation-checking sheet and records the reviewer's verdict in the assessment |
| `src/config.py` | Loads `config/settings.json` and `.env` |
| `src/sources/` | **Source access**: CVE Services API, NVD API 2.0, CISA KEV feed, Tavily, with retry and cached fallback |
| `src/tools/` | **Tools**: `environment_search`, `lookup_vulnerability`, `lookup_kev`, `tavily_search`, and the runner that executes model tool requests |
| `src/llm.py`, `src/prompts.py` | **Model settings, client and prompts** (Ollama Cloud; prompts are versioned) |
| `src/orchestrator.py` | **Orchestration**: the design's workflow table, step by step |
| `src/policy.py` | **Rating logic**: Gate 1 applicability, Gate 2 likelihood x impact, confidence |
| `src/factcheck.py`, `src/validate.py` | **Validation**: facts vs saved tool outputs; output schema and cross-field checks |
| `src/assemble.py` | Builds the assessment JSON (evidence provenance is filled by code, not the model) |
| `config/settings.json` | Non-secret configuration (model, inputs, source URLs, allowed domains, limits, fault switches) |
| `Resources/` | Saved inputs: CVE record, environment snapshot (.docx and .json), output schema, cached NVD/KEV data with `cache_manifest.json` (SHA-256), source PDFs, policy-check environment variants |
| `scripts/build_policy_check_environments.py` | Regenerates the policy-check environment variants |
| `model_outputs_and_assessments/` | Saved runs (baseline and four policy checks) and the output review and comparison documents |
| `tests/` | Offline unit and end-to-end tests (scripted model), plus optional live tests |

## Requirements

- **Python 3.11** (tested on 3.11.9; 3.10 is the minimum)
- **Git**
- Internet access to `ollama.com`, `api.tavily.com`, `cveawg.mitre.org`, `services.nvd.nist.gov` and `www.cisa.gov`
- An **Ollama Cloud API key** (https://ollama.com) and a **Tavily API key** (https://tavily.com)

Tested on Windows 11 (PowerShell). The commands below also work on macOS/Linux with the path changes shown.

### Dependency versions

| Package | Version | Used for |
|---|---|---|
| requests | 2.34.2 | HTTP access to the model and sources |
| jsonschema | 4.26.0 | Output-schema and model-output validation |
| python-dotenv | 1.2.4 | Loading API keys from `.env` |
| pytest | 9.1.1 | Tests |

| Service | Version / endpoint |
|---|---|
| LLM | Ollama Cloud, model `gemma4:31b`, temperature 0, `/api/chat` with native tool calling |
| CVE record | CVE Services API `https://cveawg.mitre.org/api/cve/{cve_id}` (CVE JSON 5.2) |
| NVD | NVD CVE API 2.0 `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}` |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (cached copy: catalog 2026.10.08) |
| Web search | Tavily Search API `https://api.tavily.com/search` |

## Setup

```powershell
# 1. Clone (Windows: use a reasonably short folder path; see Troubleshooting)
git clone <repository-url> Build_a_Security_Triage_Agent
cd Build_a_Security_Triage_Agent

# 2. Virtual environment and dependencies
python -m venv .venv
.\.venv\Scripts\Activate.ps1            # macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt

# 3. API keys
Copy-Item .env.example .env             # macOS/Linux: cp .env.example .env
# then edit .env and set OLLAMA_API_KEY and TAVILY_API_KEY

# 4. Check the install (offline, about 10 seconds; no keys needed)
python -m pytest -m "not live"
```

The offline tests (143) cover the policy, the validator, every tool, the model client and the complete workflow with a scripted model. With keys in `.env`, `python -m pytest -m live` also checks each live source and confirms the model makes a real tool call.

## Configuration (no secrets)

Secrets live only in `.env`, which is gitignored:

```
OLLAMA_API_KEY=your-ollama-cloud-key
TAVILY_API_KEY=your-tavily-key
# optional: OLLAMA_MODEL=gemma4:31b   (overrides settings.json)
```

Everything else is in `config/settings.json`. A copy is saved with every run (`other_info/config.json`).

| Setting | Value | Meaning |
|---|---|---|
| `model.name` / `provider` / `base_url` | `gemma4:31b` / Ollama Cloud / `https://ollama.com` | Model service |
| `model.temperature` | `0` | Deterministic-as-possible sampling |
| `model.max_tool_rounds` | `5` | Planning/follow-up rounds (design: capped at 5) |
| `model.max_tool_calls` | `20` | Tool-call budget per run |
| `inputs.cve_id` / `asset_id` | `CVE-2026-69730` / `W01` | The case |
| `inputs.risk_question` | design's risk question | Given to the model at planning |
| `inputs.threat_input`, `inputs.environment_snapshot` | `Resources/...` | Saved inputs (copied and hashed into each run) |
| `sources.*` | URLs and cache files | Live endpoints and cached fallbacks |
| `sources.tavily.allowed_domains` | 13 vendor/government/security-vendor domains | Web search is restricted to these |
| `retry` | 2 attempts, 2 s back-off, 30 s timeout | Design: retry once, then cache |
| `fault_injection` | all `false` | Controlled-failure switches (set from the CLI, not by editing) |

## AI Disclosure
Claude was used to generate an assessment schema based on my described design and provide validation and policy checks that would help ensure the outputted results were comprehensive and accurate. It was also used to turn my workflow steps table into a workflow diagram. See here: https://claude.ai/share/ffd60cba-c1ca-46e5-9482-ba639b82eab8

Claude Code within VSCode was used to support generating the actual code for the triage agent and workflow. The relevant chat history was exported in JSONL format and is saved in the repo under the .claude folder.


## Running the complete workflow

```powershell
python run_assessment.py --run-id my_run
```

The console shows each tool call the model selected (with arguments, status and live/cached/simulated mode), the fact-validation result, the decision and policy rule, technical severity vs local risk, confidence, the recommended next step and every validation check. Exit code: `0` completed and valid, `1` completed but failed validation, `2` stopped (Review Needed).

Each run is saved to `model_outputs_and_assessments/<run-id>/`:

| File | Contents |
|---|---|
| `assessment.json` | The structured assessment (asset and threat, decision, rationale, evidence, assumptions, unknowns, confidence, action, tool trace, analyst review, validation results) |
| `tool_outputs/T#.json` | Raw output of each tool call; its SHA-256 is in the tool trace |
| `inputs/` | Copies of the threat input and environment snapshot used |
| `other_info/config.json`, `prompts.json` | Configuration and every prompt/schema used |
| `other_info/inputs.json` | SHA-256 of the saved inputs |
| `other_info/model_transcript.jsonl` | Every model request and reply, including the structured tool calls |
| `other_info/run_log.jsonl` | Step-by-step workflow events |

Re-check any saved assessment at any time:

```powershell
python src/validate.py model_outputs_and_assessments/baseline/assessment.json
```

Live model and web results can differ between runs. The saved runs in `model_outputs_and_assessments/` are the Assignment 2 baseline.

## Running the policy checks and the controlled failure

The environment variants are in `Resources/policy_check_environments/`. Regenerate them with `python scripts/build_policy_check_environments.py`. Each variant records its changes in `metadata.variant`.

```powershell
# Adjustment 1 - applicability: all four DCs patched (build 10.0.20348.5631)
python run_assessment.py --run-id adj1 --env Resources/policy_check_environments/adjustment1_patched_build.json

# Adjustment 2 - applicability: all four DCs unpatched (build 10.0.20348.5499)
python run_assessment.py --run-id adj2 --env Resources/policy_check_environments/adjustment2_unpatched_build.json

# Adjustment 3 - impact: DNS Server role on the W06 print servers instead of the DCs (unpatched; assesses W06)
python run_assessment.py --run-id adj3 --env Resources/policy_check_environments/adjustment3_impact_lower.json

# Adjustment 4 - controlled failure: CVE and NVD APIs unavailable, no cached fallback
python run_assessment.py --run-id adj4 --fail cve --fail nvd --no-cache
```

Other failure switches: `--fail kev`, `--fail tavily`, or `--fail cve --fail nvd` without `--no-cache` (falls back to the cache, labelled `cached`). A run ID must be a new folder name, or one of the empty placeholder folders; previous runs are never overwritten.

## Results and group documents

In `model_outputs_and_assessments/group_assessments/`:

- `human_v_agent_output_comparison.md` - limitations, changes from the initial design, and expected vs actual results for the baseline (missing evidence), the two applicability checks, the impact check and the controlled failure
- `analyst_manual_review_baseline.md` - the analyst's review of the baseline's evidence and scores
- `run_checklist.md` - the complete-run demonstration checklist
- `expected_assessment_output_CVE-2026-69730.json` - the group's hand-written expected assessment

## Troubleshooting

- **"Filename too long" when cloning on Windows:** the deepest repository path is about 105 characters, so clone into a folder whose path is under about 150 characters (for example `C:\Users\<you>\Downloads\`). Or run `git config --global core.longpaths true` before cloning.
- **Cached fallback rejected ("SHA-256 does not match the cache manifest"):** a cached file's bytes changed. The repository's `.gitattributes` stops git from converting line endings in `*.json`/`*.jsonl`. Do not re-save those files in an editor that changes line endings.
- **`OLLAMA_API_KEY is not set` / HTTP 401:** check `.env` is in the repository root and contains a valid key.
