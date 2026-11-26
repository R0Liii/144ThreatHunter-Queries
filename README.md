# 144ThreatHunter Queries

A new threat hunting query, most days, for the threats that are being exploited right now.

Each hunt is written for **Microsoft Defender XDR advanced hunting and Microsoft Sentinel (KQL)**, with a
portable **Sigma** rule where it makes sense. Every hunt includes its MITRE ATT&CK mapping, the sources
it was built from, known false positives, tuning advice and triage steps for when it fires.

Maintained by Jose ([@R0Liii](https://github.com/R0Liii)) · [144 Cybersecurity](https://144company.com/cyber)

Browse the [144 Threat Hunting library](https://144company.com/threat-hunting) for defensive hunt notes and queries.

## Latest hunts

<!-- latest-hunts:start -->
| Date | ID | Hunt | ATT&CK | Severity |
| --- | --- | --- | --- | --- |
| 2026-11-26 | [TH-2026-0001](hunts/2026/2026-11-26-web-server-spawning-shells) | Web server worker processes spawning shells and recon tools | T1505.003, T1059.001, T1059.003 | high |
<!-- latest-hunts:end -->

Browse everything: [by ATT&CK technique](index/by-technique.md) · [by platform](index/by-platform.md) ·
[JSON feed](feed/hunts.json)

## Using a hunt

1. Open the hunt folder and read its README: why it matters, what it looks for, and what to do when it fires.
2. Copy `query.kql` into Defender XDR advanced hunting. In Sentinel, replace `Timestamp` with `TimeGenerated`.
3. Run it over 7 to 30 days to baseline, then add your known-good exclusions from the Tuning section.
4. Not on Microsoft? Convert `query.sigma.yml` with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) for your SIEM.

Each hunt has a `validated` level:

| Level | Meaning |
| --- | --- |
| `syntax` | Passed automated checks (schema, KQL lint, Sigma parse). Not yet run against live data. |
| `lab` | Run against a lab tenant with simulated activity. |
| `production` | Run in a production environment; false positive notes reflect real data. |

## How hunts are made

Research agents watch CISA's Known Exploited Vulnerabilities catalog and advisories, new CVEs, vendor
threat research and security news. Each morning they pick the threat most worth hunting and draft a
query, which arrives here as a pull request. **Every hunt is reviewed and edited by a human before it is
merged.** Nothing publishes automatically.

The pipeline lives in [`pipeline/`](pipeline/); see [CONTRIBUTING.md](CONTRIBUTING.md) and [PLAYBOOK.md](PLAYBOOK.md).

## Disclaimer

These queries are provided as-is for defensive use. Test them in your own environment before relying on
them. Sources are linked in every hunt; all credit for the underlying research goes to their authors.

## License

[MIT](LICENSE) for queries, write-ups and pipeline code.
