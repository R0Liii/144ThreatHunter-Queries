# TH-2026-0001: Web server worker processes spawning shells and recon tools

**Date:** 2026-11-26 · **Severity:** high · **Status:** experimental · **Validated:** syntax

**Platforms:** Microsoft Defender XDR, Microsoft Sentinel · **Tables:** `DeviceProcessEvents`

**MITRE ATT&CK:** [T1505.003](https://attack.mitre.org/techniques/T1505/003/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.003](https://attack.mitre.org/techniques/T1059/003/), [T1033](https://attack.mitre.org/techniques/T1033/)

## Why hunt for this

Exploited web apps (Exchange, SharePoint, file transfer and VPN portals) usually end with a web shell that runs commands as the web server's worker process. This hunt finds IIS, Apache, nginx, Tomcat and PHP workers launching command shells, PowerShell, or common discovery and download tools.

## Query (KQL)

```kql
// TH-2026-0001 Web server worker processes spawning shells and recon tools
// Platform: Microsoft Defender XDR advanced hunting.
// For Microsoft Sentinel, replace Timestamp with TimeGenerated.
// MITRE ATT&CK: T1505.003, T1059.001, T1059.003, T1033
let lookback = 7d;
let WebWorkers = dynamic(["w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat8.exe", "tomcat9.exe", "php-cgi.exe", "UMWorkerProcess.exe"]);
let SuspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "ipconfig.exe", "quser.exe", "tasklist.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "reg.exe", "schtasks.exe"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ (WebWorkers)
| where FileName in~ (SuspiciousChildren)
// ASP.NET compilation noise is csc.exe/cvtres.exe, which are not in the child list.
// Add known-good parent command lines here after baselining:
| where not(InitiatingProcessCommandLine has_any ("<known-good-app-pool>"))
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Executions = count(),
    Children = make_set(FileName, 20),
    SampleCommands = make_set(ProcessCommandLine, 10)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Executions desc
```

A portable [Sigma version](query.sigma.yml) is included for other SIEMs.

## When it fires

1. Check the parent command line for the app pool or site name, then find the web request that matches the process start time in IIS or proxy logs.
2. Look for a new or recently modified .aspx, .ashx, .jsp or .php file in the web root around that time.
3. Review the child command line for discovery (whoami, net, nltest), download (certutil, bitsadmin, curl) or encoded PowerShell.
4. If confirmed, isolate the server, preserve the web root and logs, and hunt for the same file hash or command pattern on other servers.

## Known false positives

- ASP.NET dynamic compilation launches csc.exe and cvtres.exe from w3wp.exe (excluded in the query)
- Health-check or deployment scripts that an app pool runs on purpose
- Monitoring agents that wrap the web server process

## Tuning

Add known-good parent command lines (specific app pools or script paths) to the exclusion list, or move them to a watchlist in Sentinel. Run over 30 days first to baseline.

## Sources

- <https://attack.mitre.org/techniques/T1505/003/>
- <https://attack.mitre.org/techniques/T1059/>

---
*Validation level `syntax`: `syntax` means the query passed automated checks but has not been run against live data. Test in your own environment before relying on it.*
