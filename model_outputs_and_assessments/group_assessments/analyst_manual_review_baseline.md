# Analyst review sheet - baseline

**Asset:** W01 (Domain controllers)  
**Threat:** CVE-2026-69730 - Windows DNS Server Remote Code Execution Vulnerability  
**Decision:** Insufficient Evidence (P-IE, Gate 1)  
**Provisional:** High (P-H-L4I2) - If the OS build is found to be lower than 10.0.20348.5622, the rating will be High (P-H-L4I2).  
**Technical severity:** CVSS 9.8 Critical `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C`  
**Local risk:** Insufficient Evidence (provisional High, P-H-L4I2)  
**Confidence:** Low - Confidence is Low because a decisive applicability fact (the OS build) is missing, preventing a binding determination of whether the vulnerability exists on the asset. Policy basis: a decisive applicability fact is unknown.

> The rating is currently 'Insufficient Evidence' because the exact OS build of the Domain Controllers (W01) is unknown. While the asset runs Windows Server 2022 and the DNS Server service, we cannot determine if it is vulnerable without knowing if the build version is lower than the fixed version (10.0.20348.5622).

## Recommended action

**High** - The SOC analyst should query the OS build version of the four hosts associated with asset W01 via a host scan or system query.

- If OS build < 10.0.20348.5622: Rating becomes High (P-H-L4I2)
- If OS build >= 10.0.20348.5622: Rating becomes Low/Not Applicable (P-NA)

## Applicability (Gate 1)

| Condition | Result | Basis | Evidence | Confirmed |
|---|---|---|---|---|
| C1 The OS is in the affected products list | **true** | The asset runs Windows Server 2022, which is listed as an affected product for CVE-2026-69730. | E7, E19 | Y |
| C2 The DNS Server service is installed | **true** | The DNS Server service is explicitly listed as installed on asset W01. | E3 | Y |
| C3 The OS build is below the fixed build (10.0.20348.5622) | **unknown** | The OS build for asset W01 is not provided in the asset record. | E20 | Y |

## Likelihood x Impact (Gate 2, provisional)

| Factor | Score | Basis | Evidence | Confirmed |
|---|---|---|---|---|
| reachability | 1 | The asset is not internet-exposed, but it is reachable from all internal client and server zones via DNS ports (53/tcp, 53/udp). | E21, E22, E23 | E23: Assumed, nowhere is it stated that port 53 is open but given that the domain controllers and domain-joined devices support DNS this is likely the case. |
| exploitability | 2 | AV:N AC:L PR:N UI:N scores 2 (0 = AV:L/P; 1 = AV:N/A otherwise; 2 = AV:N/A with AC:L, PR:N, UI:N). | E14, E15, E16, E17, E18 | Y |
| exploit_activity | 1 | The CVE is not in KEV, and Microsoft reports no public disclosure or active exploitation, but assesses exploitation as 'More Likely'. | E24, E25 | Y |
| asset_criticality | 2 | The asset is a Tier 0 Domain Controller supporting the 'Identity and privileged management' business service, which is critical for authentication across 1,000 staff. | E6, E27 | E6: Partial, asset is critical both in importance (IDENTITY) and reach, but nowhere is it specified that the domain controllers are tier 0. |
| blast_radius | 2 | As a Domain Controller, compromise affects the entire domain/organization, including all domain-joined endpoints and servers. | E28 | Y |

Likelihood 4 (Medium), Impact 2 (High), matrix -> High (P-H-L4I2)
- ADJ-RTO: RTO <= 4 hours raises impact one level - input 4 (known); Triggered but not binding: impact was already at the maximum. Evidence: E26. Confirmed: E26: Y, not sure where the BS01 came from, should just be S05.
- ADJ-CIA: All CVSS C/I/A Low or None lowers impact one level - input C:H/I:H/A:H (known); Not triggered. Confirmed: Y

## Evidence

| ID | Fact (model) | Source | Mode | Confirmed |
|---|---|---|---|---|
| E1 | The asset ID is W01. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E2 | The asset name is Domain controllers. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E3 | The asset runs AD DS, DNS Server, Kerberos, and Group Policy. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E4 | There are 4 hosts for this asset. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E5 | The asset is distributed across HQ (2) and RECOVERY (2) sites. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E6 | The asset is Tier 0. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Partial, asset is critical both in importance (IDENTITY) and reach, but nowhere is it specified that the domain controllers are tier 0. |
| E7 | The operating system is Windows Server 2022. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E8 | The network zone is IDENTITY. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E9 | The search for 'DNS Server' matched only asset W01 out of 44 assets searched, and the register is complete at cohort level. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E10 | The CVE ID is CVE-2026-69730. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E11 | The vulnerability is titled Windows DNS Server Remote Code Execution Vulnerability. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E12 | The affected component is Windows DNS. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E13 | The fixed build for Windows Server 2022 is 10.0.20348.5622. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E14 | The CVSS version is 3.1. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E15 | The base score is 9.8. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E16 | The base severity is Critical. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E17 | The CVSS vector is CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E18 | The source is microsoft (CNA) via CVE record. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E19 | Windows Server 2022 is listed as an affected product. | CVE Program (cvelistV5) via lookup_vulnerability<br>https://cveawg.mitre.org/api/cve/CVE-2026-69730 | live | Y |
| E20 | The os_build for asset W01 is null. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E21 | Internet exposure is none. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E22 | The source for DNS traffic is Domain-joined devices (all internal client and server zones). | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E23 | Ports 53/tcp and 53/udp are open to the asset. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Assumed, nowhere is it stated that port 53 is open but given that the domain controllers and domain-joined devices support DNS this is likely the case. |
| E24 | The CVE is not listed in KEV. | CISA KEV via lookup_kev<br>https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | live | Y |
| E25 | Microsoft reports 'Publicly disclosed No', 'Exploited No', and 'Exploitability assessment Exploitation More Likely'. | msrc.microsoft.com via tavily_search<br>https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2026-69730 | live | Y |
| E26 | The RTO for BS01 is 4 hours. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y, not sure where the BS01 came from, should just be S05. |
| E27 | Identity outage can block new logins across 1,000 staff. | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
| E28 | Dependents include all domain-joined endpoints and servers (authentication, DNS, Group Policy). | Northbridge environment via environment_search<br>Resources/windows_enterprise_environment.json | simulated | Y |
