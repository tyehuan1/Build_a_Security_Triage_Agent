"""Run the security triage agent end to end.

Examples:
    python run_assessment.py                                  # the configured case (CVE-2026-69730 on W01)
    python run_assessment.py --fail nvd --fail cve            # controlled failure: CVE/NVD APIs down (cache fallback)
    python run_assessment.py --fail cve --fail nvd --no-cache # controlled failure with no cache -> P-RV-F
    python run_assessment.py --env path/to/variant.json --run-id applicability-check

Outputs go to runs/<run_id>/ (assessment.json, tool_outputs/, model_transcript.jsonl, run_log.jsonl, ...).
Exit code: 0 completed and valid, 1 completed but failed validation, 2 stopped (Review Needed).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import config  # noqa: E402
from orchestrator import run_assessment  # noqa: E402

SOURCES = ("cve", "nvd", "kev", "tavily")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cve", help="override inputs.cve_id")
    ap.add_argument("--asset", help="override inputs.asset_id")
    ap.add_argument("--env", help="override the environment snapshot path (repo-relative)")
    ap.add_argument("--fail", action="append", choices=SOURCES, default=[], help="simulate an outage of a source (repeatable)")
    ap.add_argument("--no-cache", action="store_true", help="disable cached fallbacks")
    ap.add_argument("--run-id", help="name of the run folder under runs/")
    args = ap.parse_args()

    s = config.load_settings(overrides={"fault_injection": {**{src: True for src in args.fail}, "disable_cache": args.no_cache}})
    if args.cve:
        s["inputs"]["cve_id"] = s["inputs"]["threat_input"]["id"] = args.cve
    if args.asset:
        s["inputs"]["asset_id"] = args.asset
    if args.env:
        s["inputs"]["environment_snapshot"]["path"] = args.env

    print(f"Running {s['inputs']['cve_id']} on {s['inputs']['asset_id']} with {s['model']['name']} "
          f"(faults: {args.fail or 'none'}{', no cache' if args.no_cache else ''}) ...")
    result = run_assessment(s, run_id=args.run_id)
    print(f"Run folder: {config.path(str(result['run_dir']))}")

    if result["status"] == "stopped":
        print(f"STOPPED at {result['stage']}: Review Needed (P-RV-F) - {result['reason']}")
        return 2

    a = result["assessment"]
    d = a["decision"]
    print("\nTool calls (selected by the model, executed by code):")
    for t in a["tool_trace"]:
        args_s = ", ".join(f"{k}={v!r}" for k, v in t["arguments"].items())
        print(f"  {t['call_id']:>3} {t['tool']:<21} {t['result_status']:<15} {str(t['mode']):<9} {args_s[:70]}")
    if a["run_metadata"]["fabrication_rejections"]:
        print(f"  ! {len(a['run_metadata']['fabrication_rejections'])} fabricated tool output reply(ies) rejected")
    fv = a["run_metadata"]["fact_validation"]
    print(f"\nFact validation: {'passed' if fv['passed'] else 'FAILED'} after {len(fv['attempts'])} attempt(s)")
    print(f"Decision: {d['rating']}  ({d['policy_rule_applied']}, {d['gate_reached']})")
    if d.get("provisional"):
        print(f"Provisional: {d['provisional']['rating']} ({d['provisional']['policy_rule']}) - {d['provisional']['condition']}")
    ts = a["severity_vs_local_risk"]["technical_severity"]
    print(f"Technical severity: CVSS {ts['base_score']} {ts.get('base_severity') or ''}  |  Local risk: {a['severity_vs_local_risk']['local_risk']}")
    print(f"Confidence: {a['confidence']['level']}")
    print(f"Next step: {a['action']['recommended_next_step']}")
    print("\nValidation:")
    for c in a["validation"]["checks"]:
        print(f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['check']}" + ("" if c["passed"] else f"\n         {c['detail']}"))
    print(f"\nAssessment: {result['assessment_path']}  (analyst review: pending - run review.py)")
    return 0 if result["validation_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
