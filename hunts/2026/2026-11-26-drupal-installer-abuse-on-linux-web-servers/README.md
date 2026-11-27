# TH-2026-0002: Drupal installer abuse on Linux web servers

**Date:** 2026-11-26 · **Severity:** critical · **Status:** experimental · **Validated:** syntax

**Platforms:** Microsoft Defender XDR, Microsoft Sentinel · **Tables:** `DeviceFileEvents`, `DeviceProcessEvents`

**MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/), [T1505.003](https://attack.mitre.org/techniques/T1505/003/), [T1059.004](https://attack.mitre.org/techniques/T1059/004/)

## Why hunt for this

Drupal core before 10.6.22, 11.3.22 and 11.4.13 lets an anonymous attacker use install.php to try to reinstall a live site, leading to takeover or code execution (CVE-2026-132165). Exploitation was reported from 19 November 2026 and CISA added it to KEV on 24 November. With no published indicators, this hunt looks on Linux web servers for settings.php written by PHP, PHP files under sites/*/files, and shells spawned by PHP workers on those hosts.

## Threat

- **Name:** Drupal core installer remote code execution (SA-CORE-2026-017)
- **CVEs:** CVE-2026-132165

## Query (KQL)

```kql
// TH-2026-0002 Drupal installer abuse on Linux web servers
// Platform: Microsoft Defender XDR advanced hunting (Defender for Endpoint on Linux web servers)
// For Microsoft Sentinel, replace Timestamp with TimeGenerated.
// MITRE ATT&CK: T1190, T1505.003, T1059.004
// Drupal installer abuse (CVE-2026-132165, SA-CORE-2026-017): settings.php rewritten by the
// web server, PHP files dropped under sites/*/files, and shells spawned by PHP workers on the
// same hosts.
let lookback = 14d;
let webWorker = @"^(php(-fpm|-cgi)?[0-9.]*|lsphp[0-9.]*|httpd|apache2|nginx|frankenphp)$";
let shellOrTool = dynamic(["sh","bash","dash","zsh","curl","wget","python","python3","perl","nc","ncat","socat","base64","chmod","crontab","id","whoami","uname"]);
let SettingsWrites = DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FileName in~ ("settings.php", "settings.local.php")
    | where FolderPath has "/sites/"
    | where InitiatingProcessFileName matches regex webWorker
    | extend Signal = "settings.php written by web server process", Detail = FolderPath;
let PhpInFiles = DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath has "/sites/" and FolderPath has "/files/"
    | where FileName matches regex @"(?i)\.(php[0-9]?|phtml|phar|inc)$"
    | extend Signal = "PHP file written under Drupal files directory", Detail = FolderPath;
let DrupalHosts = union SettingsWrites, PhpInFiles | distinct DeviceId;
let WorkerShells = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where DeviceId in (DrupalHosts)
    | where InitiatingProcessFileName matches regex webWorker
    | where FileName in~ (shellOrTool)
    | extend Signal = "PHP or web server worker spawned shell or tool", Detail = ProcessCommandLine;
union SettingsWrites, PhpInFiles, WorkerShells
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Events = count(),
    Signals = make_set(Signal), Details = make_set(Detail, 20),
    Initiators = make_set(InitiatingProcessCommandLine, 10),
    Accounts = make_set(InitiatingProcessAccountName, 5)
    by DeviceId, DeviceName
| extend SignalCount = array_length(Signals)
| order by SignalCount desc, LastSeen desc
```

A portable [Sigma version](query.sigma.yml) is included for other SIEMs.

## When it fires

1. Confirm the Drupal core version on the host; anything below 10.6.22, 11.3.22 or 11.4.13 is exposed if install.php is reachable.
2. Compare settings.php with version control or a backup: look for a database host, name or credentials you do not recognise.
3. Check web access logs for /core/install.php and /install.php requests around FirstSeen, and note the client IPs.
4. Review user 1 and any administrator accounts created after 18 November, plus newly enabled modules.
5. List PHP files under sites/*/files and any PHP files modified in the web root in the last two weeks, and inspect them for web shell code.
6. If confirmed, take the site offline, preserve logs and the web root, rotate database and admin credentials, block install.php in the web server config and patch.

## Known false positives

- A deliberate new install or rebuild, where the installer legitimately writes settings.php through php-fpm
- Hosting panels or one-click installers (cPanel Softaculous and similar) that write settings.php through PHP
- Modules that write generated PHP into sites/*/files, such as compiled Twig templates under files/php/twig
- Cron or drush tasks run as the web server user that call shell utilities (drush itself runs under php)

## Tuning

Exclude the compiled Twig cache path (sites/*/files/php/twig/) if it is noisy in your estate, but review it first, since attackers can hide files there. Add known build hosts or deployment windows as exclusions. The DrupalHosts scoping means the shell branch only fires on devices that also had a Drupal file signal; remove the DeviceId filter to hunt PHP worker shells on all Linux servers. If you collect web access logs in Sentinel, add a branch for requests to /core/install.php or /install.php on production sites, especially POST requests and runs of 200 responses from one client since 18 November.

## Sources

- <https://horizon3.ai/attack-research/vulnerabilities/cve-2026-132165/>
- <https://safeguard.sh/resources/blog/drupal-core-cve-2026-132165-install-php-rce-kev>
- <https://windowsforum.com/news/cve-2026-132165-drupal-installer-rce-under-active-exploitation-patch-and-block-install-php.454043/>

---
*Validation level `syntax`: `syntax` means the query passed automated checks but has not been run against live data. Test in your own environment before relying on it.*
