# TH-2026-0003: Scheduled tasks launching encoded PowerShell

**Date:** 2026-11-27 · **Severity:** medium · **Status:** experimental · **Validated:** syntax

**Platforms:** Microsoft Defender XDR, Microsoft Sentinel · **Tables:** `DeviceProcessEvents`

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

## Why hunt for this

eSentire observed Vinci RAT persist through a scheduled task that ran obfuscated PowerShell. The hunt looks for a related behavior: Windows Task Scheduler directly launching PowerShell with an encoded-command switch. A match is a lead for investigating the task and its origin. The query covers a subset of scheduled PowerShell activity and has no campaign-specific indicators.

## Query (KQL)

```kql
// TH-2026-0003 Scheduled tasks launching encoded PowerShell
// Platform: Microsoft Defender XDR
// For Microsoft Sentinel, replace Timestamp with TimeGenerated.
// MITRE ATT&CK: T1053.005, T1059.001
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName =~ "taskeng.exe"
    or (InitiatingProcessFileName =~ "svchost.exe"
        and InitiatingProcessCommandLine matches regex @"(?i)(^|[ \t])-s[ \t]+schedule($|[ \t])")
| where ProcessCommandLine matches regex @"(?i)(^|[ \t])-(encodedcommand|enc|e)[ \t]+"
| project Timestamp, DeviceId, DeviceName, ReportId, AccountDomain, AccountName,
    FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessId, InitiatingProcessCommandLine
| order by Timestamp desc
```

A portable [Sigma version](query.sigma.yml) is included for other SIEMs.

## When it fires

1. Match the time and process on the device to the Task Scheduler Operational log. Review the task name, action, principal and trigger.
2. If Security event auditing is enabled, inspect 4698 and 4702 to establish when the task was created or changed and by which account.
3. Inspect the captured command as text in an approved analysis environment. Compare the action with approved deployment records and review related Defender activity around the launch.

## Known false positives

- Backup, update, or endpoint-management tasks that encode PowerShell commands to handle nested quoting.
- Internal maintenance tasks registered by approved configuration-management accounts.

## Tuning

Requires Defender for Endpoint process creation telemetry. Use the Sentinel version only where DeviceProcessEvents is ingested. The Sigma backend needs image paths, child and parent command lines, and support for case-insensitive regex modifiers. Start at seven days or narrow to one day on large fleets. Confirm normal Task Scheduler parent processes on representative Windows builds. Exclude approved tasks only after linking their task definitions to a documented account and action. The query can miss indirect launches through wrapper processes, incomplete parent telemetry, and obfuscation without a matched encoded-command switch.

## Sources

- <https://www.esentire.com/blog/vinci-rat-lives-in-the-microsoft-store>
- <https://attack.mitre.org/detectionstrategies/DET0441/>
- <https://attack.mitre.org/techniques/T1059/001/>
- <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table>
- <https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceprocessevents>

---
*Validation level `syntax`: `syntax` means the query passed automated checks but has not been run against live data. Test in your own environment before relying on it.*
