"""Triage: list today's best candidate threats from the intel store. No AI, no cost.

Usage: python -m pipeline.triage --store intel/intel.json [--top 15] [--json candidates.json]

Scores recent items by source weight, KEV status, ransomware use and recency, and drops
anything already covered by an existing hunt (same CVE or same source URL). The daily Claude
session reads this list and chooses one (see PLAYBOOK.md).
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from pipeline.common import ROOT, all_hunts, read_json, write_json


def score(item: dict, now: datetime) -> float:
    age_days = max((now - datetime.fromisoformat(item["published"])).total_seconds() / 86400, 0)
    s = item.get("weight", 1.0)
    s += 2.0 if item.get("kev") else 0
    s += 1.0 if item.get("ransomware") else 0
    s += 0.5 if item.get("cves") else 0
    return s / (1 + age_days / 3)


def candidates(store: dict, top: int) -> list[dict]:
    hunts = all_hunts()
    covered_cves = {c for h in hunts for c in h.meta["threat"].get("cves", [])}
    covered_urls = {u for h in hunts for u in h.meta.get("sources", [])}
    now = datetime.now(timezone.utc)
    items = [
        i for i in store["items"].values()
        if i["url"] not in covered_urls and not (set(i.get("cves", [])) & covered_cves)
    ]
    for i in items:
        i["score"] = round(score(i, now), 3)
    items.sort(key=lambda i: i["score"], reverse=True)
    return items[:top]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--store", default=str(ROOT / "intel" / "intel.json"))
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--json", help="also write the candidates to this file")
    args = parser.parse_args(argv)

    cands = candidates(read_json(Path(args.store), {"items": {}}), args.top)
    if args.json:
        write_json(Path(args.json), cands)
    if not cands:
        print("no new candidates")
        return 2
    for n, c in enumerate(cands):
        flags = ", ".join(f for f, on in (("KEV", c.get("kev")), ("ransomware", c.get("ransomware")),
                                          ("RESEARCH-ONLY", not c.get("publishable", True))) if on)
        print(f"[{n}] score {c['score']} | {c['published'][:10]} | {c['source']}{' | ' + flags if flags else ''}")
        print(f"    {c['title']}")
        if c.get("cves"):
            print(f"    CVEs: {', '.join(c['cves'])}")
        print(f"    {c['url']}")
        if c.get("summary"):
            print(f"    {c['summary'][:300]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
