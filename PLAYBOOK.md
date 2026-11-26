# Daily hunt playbook

The scheduled Claude session follows this every morning. A human can follow it too.
Nothing here publishes anything: the output is a pull request that Jose reviews and merges.

## 1. Set up

```bash
pip install -r requirements.txt
git fetch origin intel && git worktree add intel origin/intel   # intel store from collect.yml
python -m pipeline.triage --store intel/intel.json --top 15
```

Triage only lists **critical and high** threats. Clutter (product news, webinars, roundups,
low-impact bugs) and things an EDR or SIEM can't see (industrial control / OT gear) are
already filtered out. Each line shows its severity, source kind and why it qualified.

If the intel branch is missing or empty, use web search for critical and high threats from the
last 72 hours (vendor intrusion and campaign write-ups, CISA advisories, CISA KEV additions).

If triage prints "no critical or high candidates today", or none of the candidates can be
hunted in Defender XDR or Sentinel, skip the day: open no PR and report why. A missed day is
better than a weak hunt.

Skip the day (open no PR) if an open PR labelled `daily-hunt` from today already exists.

## 2. Pick one threat

This is a threat hunting library, not a CVE feed. Hunt how attackers behave.

Choose the candidate that gives SOC analysts the most useful hunt today:
- **critical or high only**; the hunt's `severity` must be `critical` or `high`;
- attacker behavior first: intrusion write-ups, ransomware and APT campaigns, phishing and
  identity attacks (token theft, MFA bypass, OAuth abuse), malware and loaders, living off the
  land, edge-device exploitation followed by post-exploitation activity;
- when the lead is a CVE, hunt what attackers do with it (the child processes, web shells,
  sign-ins, persistence and network activity after exploitation), not just the vulnerable
  version. Pick a bare CVE only when nothing behavior-based is as strong that day;
- confirmed exploitation in the wild (CISA KEV, vendor incident reports) over theoretical bugs;
- observable host, identity, email or network behavior that Defender XDR or Sentinel tables
  record (process, file, registry, network, sign-in, email events);
- broad exposure (common enterprise products) and recency;
- not already covered by a hunt in `hunts/`.

## 3. Research

Read the lead, then the vendor advisory, CISA advisory and any technical write-up with
behavior or indicators. Rules:
- Every factual claim must come from a page you actually opened. List only those pages in
  `sources`, primary sources first. Never invent CVEs, actors, file names or indicators.
- **Source policy:** domains under `research_only` in `pipeline/source_policy.yml` (for example
  Ransomware.live) may be read as leads but must never be cited, linked, quoted or named in
  anything you write, including the LinkedIn post. Find a publishable source for each claim.
  CISA KEV, CISA advisories and abuse.ch (Feodo Tracker, CC0) are fine.
- Do not copy vendor detection logic verbatim; write your own and link theirs.

## 4. Write the hunt

Write `spec.json` (fields listed at the top of `pipeline/new_hunt.py`):
- Hunt behavior (process lineage, command lines, file writes, network patterns, sign-ins)
  rather than only hashes or IPs. Published indicators can be an extra `let` list.
- KQL targets Defender XDR advanced hunting (`Timestamp`). Header comment lines: platform,
  "For Microsoft Sentinel, replace Timestamp with TimeGenerated.", and
  `MITRE ATT&CK: <technique ids>`. Use only real tables and columns, include a time filter,
  prefer `has`/`in~`, and end with summarize or project so results are triageable.
- Sigma: valid rule with `attack.*` tags for each technique, or "" when the logic doesn't translate.
- False positives and tuning: concrete, not generic.
- `linkedin_post`: under 1,300 characters. First line is a hook naming the threat, then 3 short
  lines (what it is, what the hunt looks for, who should run it), then `{HUNT_URL}` on its own
  line and 3 to 5 hashtags. Plain and confident, no hype, no emoji.
- `why_today` (one or two sentences) and `source_item` (the lead you picked).

Then run:

```bash
python -m pipeline.new_hunt spec.json --pr-body pr_body.md
```

Fix every error it reports and run it again until it passes. Warnings are fine to leave if
explained in the PR. Do not commit `spec.json` or `pr_body.md`.

## 5. Open the pull request

```bash
branch="hunt/$(date -u +%Y-%m-%d)"
git checkout -b "$branch"
git add hunts index feed README.md drafts
git commit -m "hunt: <id> <title>"
git push -u origin "$branch"
```

Open a PR to `main` titled `<id>: <title>` with `pr_body.md` as the body, label it
`daily-hunt`, and assign it to R0Liii. Never merge it and never post to LinkedIn.
