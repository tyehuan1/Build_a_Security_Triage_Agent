# Human vs agent output comparison

The baseline, three policy checks, and controlled failure all led to results in line with the human assessment. The policy rule triggered was the same in all cases and the recommendations are similar. There were minor differences in the evidence such as the agent not finding the patch page from tavily_search, in assumptions where the model agent didn't consider certain factors not described in the environment as assumptions (for example that none of the DNS servers were internet reachable), and in the interim recommendation where the human assessment encourage temporary restrictions on port 53 while the agent just recommended monitoring.

The run checklist based on my design criteria for success can be found at [`run_checklist.md`](run_checklist.md)

## Limitations

- W01 Domain Controllers are assessed as one cohort. The scenario does not "assert identical settings on every host" and given that there are 2 at HQ and 2 at Recovery it's possible that the different domain controllers could have different configurations or patch statuses.
- The CVSS score is only from Microsoft. This vulnerability was chosen because it is a new and severe vulnerability, but details are still somewhat lacking due to that new status.
- The tavily_search tool has no protections against injection attacks.
- The exploit activity score is relatively broad, CTI enrichment could have provided additional details / gradation for this.
- Reachability covers only inbound network traffic to port 53. While this is the default based on the information given, if they resolve external names using domain forwarding it's possible that reachability is higher than what was described.
- More broadly the simulated environment was missing significant details. Things like network flow, build status, KBs, would all allow for greater levels of detail and specificity.

## Changes from initial design

While the primary change from my initial design to the current codebase were more general details related to specificity and testing, a few other changes include:

- The design listed an "Urgent" category. This ended up getting wrapped under high.
- The final version capped the number of tool calls at 20 to prevent high token burn or getting trapped in a loop.
- The tavily_search tool had a narrowly scoped allow list of 13 sites (microsoft and security vendors primarily) to help focus its results. It would need widening or removing the domain restriction to be fully generalizable across all threats.
- The environment_search tool was modified to be more organized and retrieve results in a consistent and easily parsable manner.
- C3 was changed to be more general (not referencing the exact build number) so that the agent couldn't cheat and find the patched build that way.

## Baseline comparison

This run looks at the baseline case, and because one of the decisive facts requires knowing the exact build of the affected assets it tests the missing evidence criteria. Overall, results and policy rule applied are consistent with the expected findings. Full details can be seen in the table below.

Run: [`../baseline/assessment.json`](../baseline/assessment.json)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | Insufficient Evidence / P-IE | Insufficient Evidence / P-IE | Yes |
| Provisional | High, P-H-L4I2 | High, P-H-L4I2 | Yes |
| C1 / C2 / C3 | true / true / unknown | true / true / unknown | Yes |
| Reachability / exploitability / exploit activity | 1 / 2 / 1 (likelihood = 4) | 1 / 2 / 1 (likelihood 4, Medium) | Yes |
| KEV / in the wild / PoC / vendor likely | false / false / false / true | false / false / false / true | Yes |
| Criticality / blast radius (impact) |  2 / 2 (impact = 2) | 2 / 2 (High) | Yes |
| ADJ-RTO / ADJ-CIA | RTO adjustment fires but not binding / CIA adjustment does not fire | triggered, not binding / not triggered | Yes |
| Technical severity | CVSS 3.1 9.8 Critical | CVSS 3.1 9.8 Critical (Microsoft CNA vector) | Yes |
| Scope check | Only W01 runs DNS Server | "only W01 ... among 44 assets searched" | Yes |
| Confidence | Medium | Low | No, but this was an error in the manual assessment. The policy rule describes that when a decisive fact is missing (such as the build number used to determine applicability) then the confidence is always low. |
| Fix | Upgrade domain controller builds to KB5122882 / 10.0.20348.5622 | KB null, 10.0.20348.5622 | Partial, the model did not cite the KB page (the Tavily query did not target it) |
| Assumptions | Assumes all DCs run DNS and are configured the same and that DNS is not Internet-reachable | none recorded | Differs, the agent treated both of these as facts which is not a given based on the language within the simulated environment document. However, given that confidence was already low for this run, this does not affect any of the output / conclusions |
| Priority | High | High | Yes |
| Interim measures | Restrict inbound traffic to port 53 to only necessary sources and monitor DNS / domain controller behaviour | Monitor DNS traffic on 53/tcp+udp | Partial, the analyst review recommended restricting internal access to port 53 as much as possible to necessary uses. The agent just recommended monitoring Port 53 for incoming connections. |

## Adjustment 1 - Patched Build

This run tests a change in applicability by specifying that the domain controllers are above the patched build. This leads to a changed result at gate 1 where rather than receiving an insufficient evidence warning we instead recieve a not applicable warning (which defaults to a risk score of Low).

Run: [`../adjustment1_patched_build/assessment.json`](../adjustment1_patched_build/assessment.json) - environment variant `Resources/policy_check_environments/adjustment1_patched_build.json` (all four DCs at OS build 10.0.20348.5631, KB5129237)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | Not Applicable / P-NA | Low / P-NA | Yes |
| Provisional | N/A | None (Gate 2 not evaluated after P-NA) | Yes |
| C1 / C2 / C3 | true / true / false | true / true / false | Yes |
| Reachability / exploitability / exploit activity | N/A (Would be same as baseline of 1/2/1) | Not evaluated (P-NA ends at Gate 1) | Yes |
| KEV / in the wild / PoC / vendor likely | N/A (Would be same as baseline of false / false / false / true) | Not evaluated (P-NA ends at Gate 1) | Yes |
| Criticality / blast radius (impact) | N/A (Would be same as baseline of 2/2) | Not evaluated (P-NA ends at Gate 1) | Yes |
| ADJ-RTO / ADJ-CIA | N/A (Would be same as baseline where RTO adjustment fires but not binding and CIA adjustment does not fire) | Not evaluated (P-NA ends at Gate 1) | Yes |
| Technical severity | 9.1 CVSS 3.1 score | CVSS 3.1 9.8 Critical | Yes |
| Scope check | Only W01 runs DNS Server | "No other assets were found running the DNS Server service" (text search for DNS Server) | Yes |
| Confidence | Mediun | High | I expected lower confidence given that the environment lacks some details that may be relevant for determining risk. However, the agent has a hard time identifying that assumptions from the environment exist which led to high confidence here |
| Fix | N/A | KB null, 10.0.20348.5622 | No, the model did not need to give a fix recommendation as the build is already above the patched level |
| Assumptions | Assumes all DCs run DNS and are configured the same and that DNS is not Internet-reachable | none recorded | Differs, the agent treated both of these as facts which is not a given based on the language within the simulated environment document. However, given that confidence was already low for this run, this does not affect any of the output / conclusions |
| Priority | Low | Low | Yes |
| Interim measures | None | none (next step: no remediation required; verify the build is consistent across all 4 hosts) | No, the interim measure recommended here of verifying the build status is a good suggestion though |

## Adjustment 2 - Unpatched Build

This run tests a change in applicability by specifying that the domain controllers are below the patched build. This leads to a changed result at gate 1 where rather than receiving an insufficient evidence warning we instead proceed to gate 2 and end up with final rather than provisional score of P-H-L4I2. The score itself remains the same between the provisional baseline and this version.

Run: [`../adjustment2_unpatched_build/assessment.json`](../adjustment2_unpatched_build/assessment.json) - environment variant `Resources/policy_check_environments/adjustment2_unpatched_build.json` (all four DCs at OS build 10.0.20348.5499, KB5120242)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | High / P-H-L4I2  | High / P-H-L4I2 | Yes |
| Provisional | N/A | None (rating is binding) | Yes |
| C1 / C2 / C3 | true / true / true | true / true / true | Yes |
| Reachability / exploitability / exploit activity | 1 / 2 / 1 (likelihood = 4) | 1 / 2 / 1 (likelihood 4, Medium) | Yes |
| KEV / in the wild / PoC / vendor likely | false / false / false / true | false / false / false / true | Yes |
| Criticality / blast radius (impact) | 2 / 2 (impact = 2) | 2 / 2 (High) | Yes |
| ADJ-RTO / ADJ-CIA | RTO adjustment fires but not binding, CIA adjustment does not fire | triggered (RTO 4h), not binding / not triggered | Yes |
| Technical severity | 9.1 CVSS 3.1 score | CVSS 3.1 9.8 Critical | Yes |
| Scope check | Only W01 runs DNS Server | "No" (text search for DNS Server) | Yes, although agent gave less details this time |
| Confidence | Medium | High | I expected lower confidence given that the environment lacks some details that may be relevant for determining risk. However, the agent has a hard time identifying that assumptions from the environment exist which led to high confidence here |
| Fix | Upgrade domain controller builds to KB5122882 / 10.0.20348.5622 | KB null, 10.0.20348.5622 | Partial, the model is missing the KB number but that was not explicitly required |
| Assumptions | Assumes all DCs run DNS and are configured the same and that DNS is not Internet-reachable | none recorded | Differs, the agent treated both of these as facts which is not a given based on the language within the simulated environment document. However, given that confidence was already low for this run, this does not affect any of the output / conclusions |
| Priority | High | High | Yes |
| Interim measures | Restrict inbound traffic to port 53 to only necessary sources and monitor DNS / domain controller behaviour | Monitor DNS traffic for anomalous patterns; restrict DNS management access to trusted administrative hosts | Partial, lightly different wording than some of the other runs, a little less specific in recommendation and doesn't give a port number |

## Adjustment 3 - Exposed Asset Change

This run tests a change in imapct by changing the exposed asset from the domain controllers to the printers (and assuming they are unpatched to pass gate 1) This leads to a similar result as gate 2 but the impact is assessed at 1 / 1 for criticality and blast radius rather than 2 / 2 since the print servers are not tied into identity like the domain controllers and may not have company wide blast radius like them.

Run: [`../adjustment3_impact_lower/assessment.json`](../adjustment3_impact_lower/assessment.json) - environment variant `Resources/policy_check_environments/adjustment3_impact_lower.json` (DNS Server role moved from the DCs to the W06 print servers, W06 unpatched at 10.0.20348.5499, internal-only DNS flow F17; assessed asset W06)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | Medium / P-M-L4I1  | Medium / P-M-L4I1 | Yes |
| Provisional | N/A | None (rating is binding) | Yes |
| C1 / C2 / C3 | true / true / true | true / true / true | Yes |
| Reachability / exploitability / exploit activity | 1 / 2 / 1 (likelihood = 4) | 1 / 2 / 1 (likelihood 4, Medium) | Yes |
| KEV / in the wild / PoC / vendor likely | false / false / false / true | false / false / false / true | Yes |
| Criticality / blast radius (impact) | 0 / 1 (impact = 1) | 1 / 1 (Medium) - S05 business-important; blast radius = internal name resolution service | disagreement on criticality but overall impact score is unchanged |
| ADJ-RTO / ADJ-CIA | Neither adjustment fires | not triggered (RTO 24h) / not triggered | Yes |
| Technical severity | 9.1 CVSS 3.1 score | CVSS 3.1 9.8 Critical | Yes |
| Scope check | Only W06 runs DNS Server | "Unknown; no environment-wide search for 'DNS Server' was performed" (first extraction cited an asset-ID lookup and was rejected by fact validation) | No, the change in the exposed asset led to a fact validation issue as the search still saw the old environemnt details of W01 as the exposed asset |
| Confidence | Medium | High | I expected lower confidence given that the environment lacks some details that may be relevant for determining risk. However, the agent has a hard time identifying that assumptions from the environment exist which led to high confidence here |
| Fix | Upgrade domain controller builds to KB5122882 / 10.0.20348.5622 ? | KB null, 10.0.20348.5622 | Partial, the model is missing the KB number but that was not explicitly required |
| Assumptions | Assumes the printers are running Windows Server 2022, that printers are not internet accessible, and that all printers are configured the same and run DNS | none recorded | Differs, the agent treated both of these as facts which is not a given based on the language within the simulated environment document. However, given that confidence was already low for this run, this does not affect any of the output / conclusions |
| Priority | Normal | Normal | Yes |
| Interim measures | Restrict inbound traffic to port 53 to only necessary sources and monitor print server behaviour | Restrict DNS traffic to W06 to only known authorized internal segments if possible | Partial, recommends the restriction but the interim recommendation doesn't include any monitoring |

## Adjustment 4 - Controlled Failure

This run tests a controlled failure where the lookup_vulnerability tool fails because the APIs are unavailable and there is no cached fallback. This leads to a policy rule of P-RV-F letting us know a tool fail and most of the expected results are N/A because it hits this failure at the first intake stage.

Run: [`../adjustment4_controlled_failure/assessment.json`](../adjustment4_controlled_failure/assessment.json) - original environment; `--fail cve --fail nvd --no-cache` (CVE and NVD APIs forced unavailable, no cached fallback)

| Field | Expected | Agent | Match |
|---|---|---|---|
| Decision / rule | P-RV-F | Review Needed / P-RV-F | Yes |
| Provisional | N/A, P-RV-F from tool failure means no conditional score | None | Yes |
| C1 / C2 / C3 | unknown / true / unknown | unknown / true / unknown | yes |
| Reachability / exploitability / exploit activity | N/A | Not evaluated (P-RV-F ends at Gate 1) | Yes |
| KEV / in the wild / PoC / vendor likely | false / false / false / true | Not evaluated (P-RV-F ends at Gate 1); lookup_kev ran live: not in KEV | No, I forgot that the P-RV-F code owuld be hit at intake so tavily_search never gets run |
| Criticality / blast radius (impact) | N/A, run doesn't get to gate 2 | Not evaluated (P-RV-F ends at Gate 1) | Yes |
| ADJ-RTO / ADJ-CIA | N/A, run doesn't get to gate 2 | Not evaluated (P-RV-F ends at Gate 1) | Yes |
| Technical severity | Failed search | Unavailable - lookup_vulnerability failed twice (T1, T9) with no cache | Yes |
| Scope check | Only W01 runs DNS Server  | "No other assets were found running the DNS Server service" (text search for DNS Server) | Yes |
| Confidence | Low | Low | Yes |
| Fix | N/A | KB null, fixed build null | Yes |
| Assumptions | N/A | none recorded | Yes |
| Priority | Medium | High | No, the only detail we have is that the vendor gave an exploitation more likely warning but nothing about the severity, thus I marked this as medium priority |
| Interim measures | N/A | Monitor DNS traffic to W01 for anomalous patterns; restrict DNS access to known internal segments where possible | No, because the applicability criteria are built in it leads to the model assuming the needed interim fixes |
