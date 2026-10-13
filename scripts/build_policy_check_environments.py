"""Build the environment variants used by the policy checks from the original snapshot.

    python scripts/build_policy_check_environments.py

Writes Resources/policy_check_environments/<variant>.json. Each file records what was changed in
metadata.variant, so the change is visible to a reviewer and to the run (environment_snapshot.id).
Adjustment 4 (controlled failure) uses the unmodified snapshot with sources forced to fail.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Resources" / "windows_enterprise_environment.json"
OUT = ROOT / "Resources" / "policy_check_environments"


def asset(env: dict, asset_id: str) -> dict:
    return next(a for a in env["assets"] if a["asset_id"] == asset_id)


def set_dc_build(env: dict, build: str, kb: str, note: str) -> dict:
    w01 = asset(env, "W01")
    w01["platform"]["os_build"] = build
    w01["platform"]["installed_kbs"] = [kb]
    w01["unknowns"] = [u for u in w01["unknowns"] if u not in ("Exact OS build per DC", "Installed KBs per DC")]
    w01["config_notes"].append(f"All four DCs report OS build {build} ({kb} installed). [policy-check variant]")
    w01["platform_basis"] = "stated (policy-check variant)"
    return env


def adjustment1(env: dict) -> dict:
    env = set_dc_build(env, "10.0.20348.5631", "KB5129237", "patched")
    env["metadata"]["variant"] = {
        "id": "adjustment1_patched_build",
        "check": "Applicability change: DCs patched",
        "changes": ["assets[asset_id=W01].platform.os_build = 10.0.20348.5631 (at/above the fixed build 10.0.20348.5622)",
                    "assets[asset_id=W01].platform.installed_kbs = [KB5129237]"],
    }
    return env


def adjustment2(env: dict) -> dict:
    env = set_dc_build(env, "10.0.20348.5499", "KB5120242", "unpatched")
    env["metadata"]["variant"] = {
        "id": "adjustment2_unpatched_build",
        "check": "Applicability change: DCs unpatched",
        "changes": ["assets[asset_id=W01].platform.os_build = 10.0.20348.5499 (below the fixed build 10.0.20348.5622)",
                    "assets[asset_id=W01].platform.installed_kbs = [KB5120242]"],
    }
    return env


def adjustment3(env: dict) -> dict:
    """The only DNS server is the print server cohort (W06), unpatched so Gate 2 gives a binding rating;
    reachability stays internal-only. Compare with adjustment 2 (unpatched DCs): only impact should change."""
    w01, w06 = asset(env, "W01"), asset(env, "W06")
    w06["platform"]["os_build"] = "10.0.20348.5499"
    w06["platform"]["installed_kbs"] = ["KB5120242"]
    w06["unknowns"] = [u for u in w06["unknowns"] if u not in ("OS builds", "Installed KBs")]
    w06["config_notes"].append("Both print servers report OS build 10.0.20348.5499 (KB5120242 installed). [policy-check variant]")
    w01["services"] = [s for s in w01["services"] if s != "DNS Server"]
    w01["tags"] = [t for t in w01["tags"] if t != "dns"]
    w01["dependents"] = ["All domain-joined endpoints and servers (authentication, Group Policy)"]
    w01["config_notes"].append("DNS Server role is not installed on the DCs; DNS is served by W06. [policy-check variant]")
    w06["services"].append("DNS Server")
    w06["tags"].append("dns")
    w06["dependents"].append("Domain-joined devices (DNS resolution)")
    w06["config_notes"].append("DNS Server role hosted on the print servers for all internal zones. [policy-check variant]")
    f09 = next(f for f in env["flows"] if f["flow_id"] == "F09")
    f09["service"] = "Kerberos, LDAP, required RPC"
    f09["ports"] = [p for p in f09["ports"] if not p.startswith("53/")]
    env["flows"].append({
        "flow_id": "F17", "source": "Domain-joined devices (all internal client and server zones)", "destination": "W06",
        "service": "DNS", "ports": ["53/tcp", "53/udp"], "purpose": "Internal name resolution",
        "basis": "policy-check variant", "source_locator": "policy-check variant (replaces the DNS part of F09)",
    })
    env["metadata"]["variant"] = {
        "id": "adjustment3_impact_lower",
        "check": "Impact change: the only exposed DNS server is the print server cohort, not the domain controllers",
        "risk_question": ("What is the risk that an unauthenticated remote code execution vulnerability in the Windows DNS "
                          "Server service (CVE-2026-69730) poses to Northbridge Services' print servers (W06), the only "
                          "assets running the DNS Server role, given their role, patch status, reachability, likelihood "
                          "of compromise, and the vulnerability's impact?"),
        "asset_id": "W06",
        "changes": ["assets[asset_id=W01].services: DNS Server removed", "assets[asset_id=W06].services: DNS Server added",
                    "assets[asset_id=W06].platform.os_build = 10.0.20348.5499 (below the fixed build), installed_kbs = [KB5120242]",
                    "flows[flow_id=F09]: DNS (53/tcp, 53/udp) removed",
                    "flows[flow_id=F17] added: domain-joined devices -> W06 DNS 53/tcp+udp (internal only, as before)"],
    }
    return env


def main() -> None:
    base = json.loads(SOURCE.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    for build in (adjustment1, adjustment2, adjustment3):
        env = build(copy.deepcopy(base))
        path = OUT / f"{env['metadata']['variant']['id']}.json"
        path.write_text(json.dumps(env, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
