"""Triage: list today's best candidate threats from the intel store. No AI, no cost.

Usage: python -m pipeline.triage --store intel/intel.json [--top 15] [--json candidates.json]
                                 [--all] [--max-kev 3]

Only critical and high threats make the list. Everything else (product news, webinars,
low-impact bugs, roundups) is dropped so the daily pick is not buried in clutter.

The list favors attacker behavior over bare CVEs: intrusion write-ups, campaigns, malware and
tradecraft from research sources score highest, and at most --max-kev entries that are only a
CVE catalog line (CISA KEV) are kept. Items already covered by a hunt (same CVE or same source
URL) are dropped. The daily Claude session reads this list and chooses one (see PLAYBOOK.md).
"""
from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from pipeline.common import ROOT, all_hunts, read_json, write_json

# Signals that an item is about a serious, active threat.
CRITICAL = [
    r"zero[- ]day", r"\b0[- ]day", r"actively exploited", r"exploited in the wild",
    r"under active exploitation", r"mass exploitation", r"emergency directive",
    r"supply[- ]chain (attack|compromise)", r"pre[- ]?auth(enticated)? (rce|remote code)",
    r"unauthenticated (rce|remote code)", r"cvss (score of )?(9\.\d|10)", r"wormable",
    r"critical (vulnerability|flaw|bug)",
]
HIGH = [
    r"ransomware", r"\bapt\s?\d*\b", r"nation[- ]state", r"state[- ]sponsored", r"threat actor",
    r"campaign", r"intrusion", r"backdoor", r"web ?shell", r"infostealer", r"\bstealer\b",
    r"credential (theft|harvest|dump)", r"phishing", r"\bloader\b", r"command[- ]and[- ]control",
    r"\bc2\b", r"lateral movement", r"exploit(ed|ation|s)?\b", r"breach", r"malware", r"trojan",
    r"\brat\b", r"botnet", r"initial access", r"persistence", r"living off the land",
    r"\blolbin", r"token theft", r"session hijack", r"mfa (bypass|fatigue)",
    r"adversary[- ]in[- ]the[- ]middle", r"\baitm\b", r"edr (killer|evasion)", r"\bbyovd\b",
    r"remote code execution", r"\brce\b", r"privilege escalation", r"authentication bypass",
    r"command injection", r"data theft", r"exfiltrat", r"wiper", r"espionage", r"hacktivist",
]
# Attacker behavior an EDR or SIEM records: these make a hunt possible.
BEHAVIOR = [
    r"\bttps?\b", r"lateral movement", r"persistence", r"powershell", r"command line",
    r"scheduled task", r"registry", r"lsass", r"\brdp\b", r"web ?shell", r"side[- ]?load",
    r"dll", r"oauth", r"\btokens?\b", r"living off the land", r"mitre", r"att&ck",
    r"indicators", r"\biocs?\b", r"hunt", r"detection", r"\bkql\b", r"sigma", r"yara",
    r"process", r"wmi", r"psexec", r"cobalt strike", r"rclone", r"remote (access|monitoring)",
    r"\brmm\b", r"entra|azure ad|active directory", r"kerberos", r"sign-?in", r"mailbox",
]
# Clutter: not a threat to hunt.
NOISE = [
    r"webinar", r"podcast", r"\baward", r"partnership", r"funding", r"acquir", r"acquisition",
    r"\blaunch(es|ed)?\b", r"now available", r"join us", r"hiring", r"predictions",
    r"year in review", r"\bdeals?\b", r"sponsored", r"best practices", r"\bsurvey\b",
    r"buyer'?s guide", r"\bconference\b", r"\bsummit\b", r"product update", r"release notes",
    r"week in review", r"newsletter", r"\bcareers?\b", r"\binterview\b", r"\bhow to\b",
]
# Not huntable with an EDR or SIEM: industrial control / OT gear, and repeats of the KEV feed.
NOT_HUNTABLE_URL = [r"/ics-advisories/", r"/ics-medical-advisories/",
                    r"known-exploited-vulnerabilit(y|ies)-catalog"]
NOT_HUNTABLE = [
    r"\bplcs?\b", r"scada", r"\bics\b", r"\bot\b devices", r"industrial control", r"refrigerat",
    r"simatic", r"ruggedcom", r"wincc", r"ecostruxure", r"danfoss", r"\bhmi\b", r"modbus",
]
SEV_BONUS = {"critical": 2.0, "high": 1.0}
KIND_BONUS = {"research": 0.75, "advisory": 0.5}


def _hits(patterns: list[str], text: str) -> list[str]:
    return [p for p in patterns if re.search(p, text)]


def feed_kinds() -> dict[str, str]:
    """Map source name to kind from feeds.yml (older stored items have no kind field)."""
    cfg = yaml.safe_load((ROOT / "pipeline" / "feeds.yml").read_text(encoding="utf-8"))
    kinds = {cfg["kev"]["name"]: cfg["kev"].get("kind", "kev")}
    kinds.update({f["name"]: f.get("kind", "news") for f in cfg["rss"]})
    return kinds


def classify(item: dict) -> tuple[str | None, list[str]]:
    """Return ("critical" | "high" | None, reasons). None means clutter: drop it."""
    text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    if _hits(NOISE, item.get("title", "").lower()):
        return None, ["noise"]
    if _hits(NOT_HUNTABLE_URL, item.get("url", "")) or _hits(NOT_HUNTABLE, text):
        return None, ["not huntable in Defender XDR / Sentinel (OT/ICS or duplicate)"]
    if item.get("kind") == "kev":
        # CISA has confirmed exploitation, so a KEV entry is never below high.
        severe = item.get("ransomware") or re.search(
            r"remote code|code execution|command injection|authentication bypass|deserializ", text)
        return ("critical" if severe else "high"), ["CISA KEV: exploited in the wild"]
    crit, high = _hits(CRITICAL, text), _hits(HIGH, text)
    if crit:
        return "critical", crit[:3]
    title_high = _hits(HIGH, item.get("title", "").lower())
    if item.get("kind") in ("research", "advisory") and (title_high or len(high) >= 2):
        return "high", high[:3]
    if len(high) >= 2:  # news needs two signals to count as high
        return "high", high[:3]
    return None, ["no critical/high signal"]


def score(item: dict, now: datetime) -> float:
    age_days = max((now - datetime.fromisoformat(item["published"])).total_seconds() / 86400, 0)
    text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    s = item.get("weight", 1.0)
    bonus = SEV_BONUS.get(item.get("severity"), 0)
    s += bonus / 2 if item.get("kind") == "kev" else bonus  # a bare CVE line ranks below behavior
    s += min(len(_hits(BEHAVIOR, text)) * 0.25, 1.5)
    s += KIND_BONUS.get(item.get("kind"), 0)
    s += 0.5 if item.get("ransomware") else 0
    return s / (1 + age_days / 5)


def candidates(store: dict, top: int, max_kev: int = 3, show_all: bool = False) -> list[dict]:
    hunts = all_hunts()
    covered_cves = {c for h in hunts for c in h.meta["threat"].get("cves", [])}
    covered_urls = {u for h in hunts for u in h.meta.get("sources", [])}
    kinds = feed_kinds()
    now = datetime.now(timezone.utc)
    items = []
    for i in store["items"].values():
        if i["url"] in covered_urls or set(i.get("cves", [])) & covered_cves:
            continue
        i.setdefault("kind", kinds.get(i["source"], "news"))
        i["severity"], i["why"] = classify(i)
        if i["severity"] or show_all:
            i["score"] = round(score(i, now), 3)
            items.append(i)
    items.sort(key=lambda i: i["score"], reverse=True)
    picked, kev_count = [], 0
    for i in items:
        if i["kind"] == "kev" and not show_all:
            if kev_count >= max_kev:
                continue
            kev_count += 1
        picked.append(i)
        if len(picked) >= top:
            break
    return picked


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--store", default=str(ROOT / "intel" / "intel.json"))
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--max-kev", type=int, default=3,
                        help="most CVE-only KEV entries allowed in the list")
    parser.add_argument("--all", action="store_true",
                        help="debug: include items filtered out as clutter")
    parser.add_argument("--json", help="also write the candidates to this file")
    args = parser.parse_args(argv)

    cands = candidates(read_json(Path(args.store), {"items": {}}), args.top, args.max_kev, args.all)
    if args.json:
        write_json(Path(args.json), cands)
    if not cands:
        print("no critical or high candidates today")
        return 2
    for n, c in enumerate(cands):
        flags = ", ".join(f for f, on in (("KEV", c.get("kev")), ("ransomware", c.get("ransomware")),
                                          ("RESEARCH-ONLY", not c.get("publishable", True))) if on)
        sev = (c.get("severity") or "filtered").upper()
        print(f"[{n}] {sev} | score {c['score']} | {c['published'][:10]} | {c['kind']} | "
              f"{c['source']}{' | ' + flags if flags else ''}")
        print(f"    {c['title']}")
        print(f"    why: {', '.join(c['why'])}")
        if c.get("cves"):
            print(f"    CVEs: {', '.join(c['cves'])}")
        print(f"    {c['url']}")
        if c.get("summary"):
            print(f"    {c['summary'][:300]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
