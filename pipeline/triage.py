"""Triage: pick today's threat from the intel store.

Usage: python -m pipeline.triage --store intel/intel.json --out pick.json

Step 1 (code): score recent items by source weight, KEV status, ransomware use, and recency,
and drop anything already covered by an existing hunt (same CVE or same source URL).
Step 2 (Claude): from the top candidates, choose the one that gives defenders the most
useful hunt today, preferring threats with host or network artifacts that KQL can see.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from pipeline.common import ROOT, all_hunts, read_json, write_json
from pipeline.llm import ask_json

TOP_N = 15

SYSTEM = """You are the triage lead for 144ThreatHunter, a public repo that publishes one
threat hunting query a day for Microsoft Defender XDR and Microsoft Sentinel (KQL).
Pick the single candidate that gives SOC analysts the most useful hunt today. Prefer:
- confirmed exploitation in the wild (CISA KEV, vendor incident reports) over theoretical bugs;
- threats with observable host, identity, email or network behavior that Defender or Sentinel
  tables record (process, file, registry, network, sign-in, email events);
- broad exposure (common enterprise products) and recency;
- topics not already covered by an existing hunt.
Avoid items with no huntable artifact (for example, a client-side bug with no post-exploitation
behavior) unless nothing better exists. Explain the choice in two or three sentences."""

PICK_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["index", "reason", "hunt_angle"],
    "properties": {
        "index": {"type": "integer", "description": "index of the chosen candidate"},
        "reason": {"type": "string"},
        "hunt_angle": {"type": "string", "description": "what behavior the query should look for"},
    },
}


def score(item: dict, now: datetime) -> float:
    age_days = max((now - datetime.fromisoformat(item["published"])).total_seconds() / 86400, 0)
    s = item.get("weight", 1.0)
    s += 2.0 if item.get("kev") else 0
    s += 1.0 if item.get("ransomware") else 0
    s += 0.5 if item.get("cves") else 0
    return s / (1 + age_days / 3)


def candidates(store: dict) -> list[dict]:
    hunts = all_hunts()
    covered_cves = {c for h in hunts for c in h.meta["threat"].get("cves", [])}
    covered_urls = {u for h in hunts for u in h.meta.get("sources", [])}
    now = datetime.now(timezone.utc)
    items = [
        i for i in store["items"].values()
        if i["url"] not in covered_urls and not (set(i.get("cves", [])) & covered_cves)
    ]
    items.sort(key=lambda i: score(i, now), reverse=True)
    return items[:TOP_N]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--store", default=str(ROOT / "intel" / "intel.json"))
    parser.add_argument("--out", default="pick.json")
    args = parser.parse_args(argv)

    cands = candidates(read_json(Path(args.store), {"items": {}}))
    if not cands:
        print("no new candidates; nothing to draft today")
        return 2
    existing = [f"{h.meta['id']}: {h.meta['title']}" for h in all_hunts()][-60:]
    listing = "\n".join(
        f"[{n}] {c['title']} | source: {c['source']} | published: {c['published'][:10]} | "
        f"KEV: {c.get('kev')} | publishable: {c.get('publishable', True)} | CVEs: {', '.join(c.get('cves', [])) or 'none'}\n"
        f"    {c['summary'][:400]}\n    {c['url']}"
        for n, c in enumerate(cands)
    )
    prompt = (f"Existing hunts (avoid repeats):\n{chr(10).join(existing) or 'none yet'}\n\n"
              f"Candidates:\n{listing}\n\nChoose one.")
    pick, _ = ask_json(SYSTEM, [{"role": "user", "content": prompt}], PICK_SCHEMA, effort="medium",
                       max_tokens=8000)
    idx = pick["index"]
    if not 0 <= idx < len(cands):
        raise SystemExit(f"triage returned an out-of-range index {idx}")
    result = {"item": cands[idx], "reason": pick["reason"], "hunt_angle": pick["hunt_angle"]}
    write_json(Path(args.out), result)
    print(json.dumps({"picked": cands[idx]["title"], "reason": pick["reason"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
