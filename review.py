"""Analyst review (design workflow step "Analyst Review", performed by a human group member).

1. Writes other_info/review_sheet.md in the run folder: the decision, conditions and scores, and every
   evidence item with its source, locator and the value found at that locator in the saved raw
   tool output, so the reviewer can check each citation against what the tool actually returned.
2. Records the reviewer's verdict in analyst_review and re-validates the assessment.

Usage:
    python review.py model_outputs_and_assessments/<run_id>/assessment.json --sheet-only        # just write the review sheet
    python review.py model_outputs_and_assessments/<run_id>/assessment.json            # sheet + interactive questions
    python review.py model_outputs_and_assessments/<run_id>/assessment.json --reviewer "Name" --status approved \\
        --citations-verified yes --agrees yes --consensus "Insufficient Evidence" --notes "..."

Rules (from the design: "Approve or override with justification"):
    approved         requires citations verified = yes and agrees with rating = yes
    changed/rejected require notes (the justification); changed also requires the consensus rating
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import config  # noqa: E402
from tools.registry import load_raw_output  # noqa: E402
from validate import validate_assessment  # noqa: E402

STATUSES = ("approved", "changed", "rejected")
RATINGS = ("High", "Medium", "Low", "Insufficient Evidence", "Review Needed")


# ---------------------------------------------------------------- locator resolution

MISSING = object()  # locator does not exist (as opposed to a real null value)


def resolve(result: dict, locator: str):
    """Value at a locator inside a tool result, or MISSING. Supports environment record locators
    (assets[asset_id=W01]...), dotted paths, [i] indexes and [key='value'] selectors."""
    loc = re.sub(r"^result\.", "", locator.split(";")[0].strip())
    if loc.startswith(("cve:", "nvd:")):
        return MISSING
    for rec in result.get("records", []):
        if rec["locator"] in loc:
            rest = loc.split(rec["locator"], 1)[1].lstrip(".")
            rest = re.sub(r"^data\.?", "", rest)  # the model sees each record wrapped as {..., "data": {...}}
            return _walk(rec["data"], rest) if rest else rec["data"]
    if loc.startswith("coverage"):
        return result.get("coverage")
    return _walk(result, loc)


def _walk(obj, path: str):
    for token in re.findall(r"[^.\[\]]+|\[[^\]]*\]", path):
        if token.startswith("["):
            inner = token[1:-1]
            if inner.isdigit() and isinstance(obj, list) and int(inner) < len(obj):
                obj = obj[int(inner)]
            elif "=" in inner and isinstance(obj, list):
                k, v = inner.split("=", 1)
                obj = next((x for x in obj if isinstance(x, dict) and str(x.get(k)) == v.strip("'\"")), MISSING)
            else:
                return MISSING
        elif isinstance(obj, dict) and token in obj:
            obj = obj[token]
        else:
            return MISSING
        if obj is MISSING:
            return MISSING
    return obj


def _excerpt(value, fact: str = "", limit=300) -> str:
    """Short text for the sheet. Long strings are centred on what the fact refers to."""
    if value is None:
        return "null (unknown)"
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    if len(text) <= limit:
        return text
    lower = text.lower()
    quoted = [a or b for a, b in re.findall(r"'([^']{4,})'|\"([^\"]{4,})\"", fact)]
    words = re.findall(r"[A-Za-z0-9.\-]+", fact)
    phrases = [" ".join(words[i:i + n]) for n in (3, 2) for i in range(len(words) - n + 1)]  # e.g. "Windows Server 2022"
    singles = sorted((w for w in words if len(w) >= 6), key=len, reverse=True)
    candidates = quoted + phrases + singles
    pos = next((lower.find(c.lower()) for c in candidates if lower.find(c.lower()) >= 0), 0)
    start = max(0, pos - limit // 3)
    return ("... " if start else "") + text[start:start + limit] + (" ..." if start + limit < len(text) else "")


# ---------------------------------------------------------------- review sheet

def review_sheet(a: dict) -> str:
    d, r = a["decision"], a["rationale"]
    trace = {t["call_id"]: t for t in a["tool_trace"]}
    lines = [f"# Analyst review sheet - {a['assessment_id']}", "",
             f"**Asset:** {a['asset']['asset_id']} ({a['asset']['asset_name']})  ",
             f"**Threat:** {a['threat']['cve_id']} - {a['threat']['title']}  ",
             f"**Decision:** {d['rating']} ({d['policy_rule_applied']}, {d['gate_reached']})  "]
    if d.get("provisional"):
        lines.append(f"**Provisional:** {d['provisional']['rating']} ({d['provisional']['policy_rule']}) - {d['provisional']['condition']}  ")
    ts = a["severity_vs_local_risk"]["technical_severity"]
    lines += [f"**Technical severity:** CVSS {ts['base_score']} {ts.get('base_severity') or ''} `{ts['vector']}`  ",
              f"**Local risk:** {a['severity_vs_local_risk']['local_risk']}  ",
              f"**Confidence:** {a['confidence']['level']} - {a['confidence']['explanation']}", "",
              f"> {d['summary']}", "", "## Applicability (Gate 1)", "", "| Condition | Result | Basis | Evidence |", "|---|---|---|---|"]
    for c in r["applicability"]["conditions"]:
        lines.append(f"| {c['id']} {c['description']} | **{c['result']}** | {c['basis']} | {', '.join(c['evidence_ids'])} |")
    if r["likelihood"]:
        lk, im = r["likelihood"], r["impact"]
        lines += ["", f"## Likelihood x Impact (Gate 2, {r['gate_2_status']})", "", "| Factor | Score | Basis | Evidence |", "|---|---|---|---|"]
        for name, f in {**lk["factors"], **im["factors"]}.items():
            lines.append(f"| {name} | {f['score']} | {f['basis']} | {', '.join(f['evidence_ids'])} |")
        lines += ["", f"Likelihood {lk['final_score']} ({lk['level']}), Impact {im['final_score']} ({im['level']}), "
                      f"matrix -> {r['matrix_result']['rating']} ({r['matrix_result']['policy_rule']})"]
        for adj in im["adjustments"]:
            lines.append(f"- {adj['id']}: {adj['rule']} - input {adj['input_value']} ({adj['input_status']}); {adj.get('note', '')}")
    lines += ["", "## Evidence - check each citation against the saved tool output", "",
              "Fill the OK? column with Y (value supports the fact) or N (it does not - note why).", "",
              "| ID | Fact (model) | Source | Mode | Locator | Value at locator in saved output | Raw output | OK? |",
              "|---|---|---|---|---|---|---|---|"]
    for e in a["evidence"]:
        t = trace[e["tool_call_id"]]
        try:
            value = resolve(load_raw_output(t)["result"], e["locator"])
        except (OSError, KeyError, TypeError, ValueError):
            value = MISSING
        shown = _excerpt(value, e["fact"]) if value is not MISSING else \
            f"(not resolvable; see {e['tool_call_id']} summary: {t['result_summary']})"
        cell = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {e['evidence_id']} | {cell(e['fact'])} | {cell(e['source_name'])}<br>{cell(e['url_or_path'])} | "
                     f"{e['retrieval_mode']} | `{cell(e['locator'])}` | {cell(shown)} | {cell(t['raw_output_path'])} |   |")
    lines += ["", "## Assumptions and unknowns", ""]
    lines += [f"- {x['id']}: {x['statement']} ({x['reason']})" for x in a["assumptions"]] or ["- No assumptions recorded."]
    lines += [f"- {u['id']}{' (decisive)' if u['decisive'] else ''}: {u['question']} - {u['how_to_resolve']}" for u in a["unknowns"]]
    lines += ["", "## Recommended action", "", f"**{a['action']['priority']}** - {a['action']['recommended_next_step']}", ""]
    lines += [f"- If {x['evidence_needed']}: {x['effect_on_decision']}" for x in a["action"]["evidence_to_resolve"]]
    lines += ["", "## Reviewer questions", "", "1. Does each value at locator support the model's fact?",
              "2. Were the conditions and scores applied according to the policy?",
              "3. Do you agree with the rating? Record approve / change / reject with justification in review.py.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- recording the review

class ReviewError(ValueError):
    pass


def apply_review(a: dict, *, reviewer: str, status: str, citations_verified: bool, agrees: bool,
                 consensus: str | None, notes: str | None) -> dict:
    if not reviewer:
        raise ReviewError("reviewer name is required")
    if status not in STATUSES:
        raise ReviewError(f"status must be one of {STATUSES}")
    if consensus is not None and consensus not in RATINGS:
        raise ReviewError(f"consensus rating must be one of {RATINGS}")
    if status == "approved" and not (citations_verified and agrees):
        raise ReviewError("'approved' requires citations verified = yes and agrees with rating = yes; use 'changed' or 'rejected'")
    if status in ("changed", "rejected") and not (notes and notes.strip()):
        raise ReviewError(f"'{status}' requires notes justifying the override")
    if status == "changed" and not consensus:
        raise ReviewError("'changed' requires the group consensus rating")
    a["analyst_review"] = {
        "status": status, "reviewer": reviewer, "reviewed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "citations_verified": citations_verified, "agrees_with_rating": agrees,
        "group_consensus_rating": consensus, "notes": notes or None,
    }
    return a


def _yes(v: str) -> bool:
    if v.strip().lower() in ("y", "yes", "true"):
        return True
    if v.strip().lower() in ("n", "no", "false"):
        return False
    raise ReviewError(f"expected yes or no, got {v!r}")


def _ask(prompt: str, current):
    return current if current is not None else input(prompt).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("assessment", type=Path)
    ap.add_argument("--sheet-only", action="store_true")
    ap.add_argument("--reviewer")
    ap.add_argument("--status", choices=STATUSES)
    ap.add_argument("--citations-verified")
    ap.add_argument("--agrees")
    ap.add_argument("--consensus", choices=RATINGS)
    ap.add_argument("--notes")
    args = ap.parse_args()

    a = json.loads(args.assessment.read_text(encoding="utf-8"))
    sheet = args.assessment.parent / "other_info" / "review_sheet.md"
    sheet.parent.mkdir(exist_ok=True)
    sheet.write_text(review_sheet(a), encoding="utf-8", newline="\n")
    print(f"Review sheet written: {sheet}")
    if args.sheet_only:
        return 0

    try:
        apply_review(
            a,
            reviewer=_ask("Reviewer name: ", args.reviewer),
            status=_ask(f"Status {STATUSES}: ", args.status),
            citations_verified=_yes(_ask("Citations verified against the saved outputs? (yes/no): ", args.citations_verified)),
            agrees=_yes(_ask(f"Agree with the rating '{a['decision']['rating']}'? (yes/no): ", args.agrees)),
            consensus=_ask(f"Group consensus rating {RATINGS} (blank = none): ", args.consensus) or None,
            notes=_ask("Notes / justification: ", args.notes) or None,
        )
    except ReviewError as err:
        print(f"Review not recorded: {err}")
        return 1

    schema = json.loads(config.path("Resources/output_schema.json").read_text(encoding="utf-8"))
    a["validation"] = validate_assessment(a, schema)
    args.assessment.write_text(json.dumps(a, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    failed = [c["check"] for c in a["validation"]["checks"] if not c["passed"]]
    print(f"Analyst review recorded ({a['analyst_review']['status']} by {a['analyst_review']['reviewer']}). "
          f"Validation: {'all checks pass' if not failed else 'FAILED: ' + '; '.join(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
