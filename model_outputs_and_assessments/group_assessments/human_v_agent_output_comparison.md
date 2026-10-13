# Human vs agent output comparison

The baseline, three policy checks, and controlled failure all led to results in line with the human assessment. The policy rule triggered was the same in all cases and the recommendations are similar. There were minor differences in the evidence such as the agent not finding the patch page from tavily_search, in assumptions where the model agent didn't consider certain factors not described in the environment as assumptions (for example that none of the DNS servers were internet reachable), and in the interim recommendation where the human assessment encourage temporary restrictions on port 53 while the agent just recommended monitoring.

The run checklist based on my design criteria for success can be found at `../baseline/run_checklist.md`

## Baseline comparison

Run: [`../baseline/assessment.json`](../baseline/assessment.json)

| Field | Expected | Agent | Match |
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
| Confidence | Medium | Low | No, but this was an error in the manual assessment. The policy rule describes that when a decisive fact is missing (such as the build number used to determine applicability) then the confidence is always low. |
| Fix | KB5122882, 10.0.20348.5622 | KB null, 10.0.20348.5622 | Partial, the model did not cite the KB page (the Tavily query did not target it) |
| Assumptions | A1 all DCs run DNS; A2 DNS not Internet-reachable | none recorded | Differs, the agent treated both of these as facts which is not a given based on the language within the simulated environment document. However, given that confidence was already low for this run, this does not affect any of the output / conclusions. |
| Priority | High | High | Yes |
| Interim measures | Restrict port 53; monitor DNS/DC behaviour | Monitor DNS traffic on 53/tcp+udp | Partial, the analyst review recommended restricting internal access to port 53 as much as possible to necessary uses. The agent just recommended monitoring Port 53 for incoming connections. |

## Adjustment 1 - Patched Build

[SUMMARY]

Run: [`../adjustment1_patched_build/assessment.json`](../adjustment1_patched_build/assessment.json) - environment variant `Resources/policy_check_environments/adjustment1_patched_build.json` (all four DCs at OS build 10.0.20348.5631, KB5129237)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | [EXPECTED] | Low / P-NA | [MATCH] |
| Provisional | [EXPECTED] | None (Gate 2 not evaluated after P-NA) | [MATCH] |
| C1 / C2 / C3 | [EXPECTED] | true / true / false | [MATCH] |
| Reachability / exploitability / exploit activity | [EXPECTED] | Not evaluated (P-NA ends at Gate 1) | [MATCH] |
| KEV / in the wild / PoC / vendor likely | [EXPECTED] | Not evaluated (P-NA ends at Gate 1) | [MATCH] |
| Criticality / blast radius (impact) | [EXPECTED] | Not evaluated (P-NA ends at Gate 1) | [MATCH] |
| ADJ-RTO / ADJ-CIA | [EXPECTED] | Not evaluated (P-NA ends at Gate 1) | [MATCH] |
| Technical severity | [EXPECTED] | CVSS 3.1 9.8 Critical | [MATCH] |
| Scope check | [EXPECTED] | "No other assets were found running the DNS Server service" (text search for DNS Server) | [MATCH] |
| Confidence | [EXPECTED] | High | [MATCH] |
| Fix | [EXPECTED] | KB null, 10.0.20348.5622 | [MATCH] |
| Assumptions | [EXPECTED] | none recorded | [MATCH] |
| Priority | [EXPECTED] | Low | [MATCH] |
| Interim measures | [EXPECTED] | none (next step: no remediation required; verify the build is consistent across all 4 hosts) | [MATCH] |

## Adjustment 2 - Unpatched Build

[SUMMARY]

Run: [`../adjustment2_unpatched_build/assessment.json`](../adjustment2_unpatched_build/assessment.json) - environment variant `Resources/policy_check_environments/adjustment2_unpatched_build.json` (all four DCs at OS build 10.0.20348.5499, KB5120242)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | [EXPECTED] | High / P-H-L4I2 | [MATCH] |
| Provisional | [EXPECTED] | None (rating is binding) | [MATCH] |
| C1 / C2 / C3 | [EXPECTED] | true / true / true | [MATCH] |
| Reachability / exploitability / exploit activity | [EXPECTED] | 1 / 2 / 1 (likelihood 4, Medium) | [MATCH] |
| KEV / in the wild / PoC / vendor likely | [EXPECTED] | false / false / false / true | [MATCH] |
| Criticality / blast radius (impact) | [EXPECTED] | 2 / 2 (High) | [MATCH] |
| ADJ-RTO / ADJ-CIA | [EXPECTED] | triggered (RTO 4h), not binding / not triggered | [MATCH] |
| Technical severity | [EXPECTED] | CVSS 3.1 9.8 Critical | [MATCH] |
| Scope check | [EXPECTED] | "No" (text search for DNS Server) | [MATCH] |
| Confidence | [EXPECTED] | High | [MATCH] |
| Fix | [EXPECTED] | KB null, 10.0.20348.5622 | [MATCH] |
| Assumptions | [EXPECTED] | none recorded | [MATCH] |
| Priority | [EXPECTED] | High | [MATCH] |
| Interim measures | [EXPECTED] | Monitor DNS traffic for anomalous patterns; restrict DNS management access to trusted administrative hosts | [MATCH] |

## Adjustment 3 - Exposed Asset Change

[SUMMARY]

Run: [`../adjustment3_impact_lower/assessment.json`](../adjustment3_impact_lower/assessment.json) - environment variant `Resources/policy_check_environments/adjustment3_impact_lower.json` (DNS Server role moved from the DCs to the W06 print servers, W06 unpatched at 10.0.20348.5499, internal-only DNS flow F17; assessed asset W06)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | [EXPECTED] | Medium / P-M-L4I1 | [MATCH] |
| Provisional | [EXPECTED] | None (rating is binding) | [MATCH] |
| C1 / C2 / C3 | [EXPECTED] | true / true / true | [MATCH] |
| Reachability / exploitability / exploit activity | [EXPECTED] | 1 / 2 / 1 (likelihood 4, Medium) | [MATCH] |
| KEV / in the wild / PoC / vendor likely | [EXPECTED] | false / false / false / true | [MATCH] |
| Criticality / blast radius (impact) | [EXPECTED] | 1 / 1 (Medium) - BS05 business-important; blast radius = internal name resolution service | [MATCH] |
| ADJ-RTO / ADJ-CIA | [EXPECTED] | not triggered (RTO 24h) / not triggered | [MATCH] |
| Technical severity | [EXPECTED] | CVSS 3.1 9.8 Critical | [MATCH] |
| Scope check | [EXPECTED] | "Unknown; no environment-wide search for 'DNS Server' was performed" (first extraction cited an asset-ID lookup and was rejected by fact validation) | [MATCH] |
| Confidence | [EXPECTED] | High | [MATCH] |
| Fix | [EXPECTED] | KB null, 10.0.20348.5622 | [MATCH] |
| Assumptions | [EXPECTED] | none recorded | [MATCH] |
| Priority | [EXPECTED] | Normal | [MATCH] |
| Interim measures | [EXPECTED] | Restrict DNS traffic to W06 to only known authorized internal segments if possible | [MATCH] |

## Adjustment 4 - Controlled Failure

[SUMMARY]

Run: [`../adjustment4_controlled_failure/assessment.json`](../adjustment4_controlled_failure/assessment.json) - original environment; `--fail cve --fail nvd --no-cache` (CVE and NVD APIs forced unavailable, no cached fallback)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | [EXPECTED] | Review Needed / P-RV-F | [MATCH] |
| Provisional | [EXPECTED] | None | [MATCH] |
| C1 / C2 / C3 | [EXPECTED] | unknown / true / unknown | [MATCH] |
| Reachability / exploitability / exploit activity | [EXPECTED] | Not evaluated (P-RV-F ends at Gate 1) | [MATCH] |
| KEV / in the wild / PoC / vendor likely | [EXPECTED] | Not evaluated (P-RV-F ends at Gate 1); lookup_kev ran live: not in KEV | [MATCH] |
| Criticality / blast radius (impact) | [EXPECTED] | Not evaluated (P-RV-F ends at Gate 1) | [MATCH] |
| ADJ-RTO / ADJ-CIA | [EXPECTED] | Not evaluated (P-RV-F ends at Gate 1) | [MATCH] |
| Technical severity | [EXPECTED] | Unavailable - lookup_vulnerability failed twice (T1, T9) with no cache | [MATCH] |
| Scope check | [EXPECTED] | "No other assets were found running the DNS Server service" (text search for DNS Server) | [MATCH] |
| Confidence | [EXPECTED] | Low | [MATCH] |
| Fix | [EXPECTED] | KB null, fixed build null | [MATCH] |
| Assumptions | [EXPECTED] | none recorded | [MATCH] |
| Priority | [EXPECTED] | High | [MATCH] |
| Interim measures | [EXPECTED] | Monitor DNS traffic to W01 for anomalous patterns; restrict DNS access to known internal segments where possible | [MATCH] |
