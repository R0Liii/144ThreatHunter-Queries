"""Collector: poll threat intel feeds into a local JSON store.

Usage: python -m pipeline.collect --store intel/intel.json [--days 30]

No AI here: plain feed polling, so it is cheap to run every few hours. Items are keyed by
URL (and by CVE for the KEV catalog) so repeated runs only add what is new.
"""
from __future__ import annotations

import argparse
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests
import yaml

from pipeline.common import ROOT, read_json, write_json

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
UA = {"User-Agent": "144ThreatHunter-collector (+https://github.com/R0Liii)"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def collect_kev(cfg: dict, since: datetime) -> list[dict]:
    data = requests.get(cfg["url"], timeout=30, headers=UA).json()
    items = []
    for v in data.get("vulnerabilities", []):
        added = datetime.fromisoformat(v["dateAdded"]).replace(tzinfo=timezone.utc)
        if added < since:
            continue
        items.append({
            "key": f"kev:{v['cveID']}",
            "source": cfg["name"],
            "weight": cfg.get("weight", 1.0),
            "title": f"{v['cveID']} {v['vendorProject']} {v['product']}: {v['vulnerabilityName']}",
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            "published": added.isoformat(),
            "summary": v.get("shortDescription", ""),
            "cves": [v["cveID"]],
            "kev": True,
            "publishable": True,
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
        })
    return items


def collect_rss(cfg: dict, since: datetime) -> list[dict]:
    resp = requests.get(cfg["url"], timeout=30, headers=UA)
    resp.raise_for_status()
    feed = feedparser.parse(resp.content)
    items = []
    for e in feed.entries:
        parsed = e.get("published_parsed") or e.get("updated_parsed")
        published = datetime(*parsed[:6], tzinfo=timezone.utc) if parsed else now()
        if published < since:
            continue
        text = f"{e.get('title', '')} {e.get('summary', '')}"
        summary = re.sub(r"<[^>]+>", " ", e.get("summary", ""))
        items.append({
            "key": f"url:{e.get('link')}",
            "source": cfg["name"],
            "weight": cfg.get("weight", 1.0),
            "title": e.get("title", "").strip(),
            "url": e.get("link"),
            "published": published.isoformat(),
            "summary": re.sub(r"\s+", " ", summary).strip()[:1000],
            "cves": sorted({c.upper() for c in CVE_RE.findall(text)}),
            "kev": False,
            "publishable": cfg.get("publishable", True),
            "ransomware": "ransomware" in text.lower(),
        })
    return items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--store", default=str(ROOT / "intel" / "intel.json"))
    parser.add_argument("--days", type=int, default=30, help="keep items this many days")
    args = parser.parse_args(argv)

    store_path = Path(args.store)
    store = read_json(store_path, {"items": {}})
    since = now() - timedelta(days=args.days)
    cfg = yaml.safe_load((ROOT / "pipeline" / "feeds.yml").read_text(encoding="utf-8"))

    sources = [("kev", cfg["kev"], collect_kev)] + [("rss", f, collect_rss) for f in cfg["rss"]]
    added = 0
    for _, feed_cfg, fn in sources:
        try:
            for item in fn(feed_cfg, since):
                if item["key"] not in store["items"]:
                    item["seen_at"] = now().isoformat()
                    store["items"][item["key"]] = item
                    added += 1
        except Exception as exc:  # one bad feed must not stop the rest
            print(f"warning: {feed_cfg['name']} failed: {type(exc).__name__}: {exc}")

    store["items"] = {k: v for k, v in store["items"].items()
                      if datetime.fromisoformat(v["published"]) >= since}
    store["updated"] = now().isoformat()
    write_json(store_path, store)
    print(f"added {added} new items; store holds {len(store['items'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
