"""Create a hunt from a JSON spec, then render and validate it.

Usage: python -m pipeline.new_hunt spec.json [--pr-body pr_body.md]

The daily Claude session (see PLAYBOOK.md) researches a threat and writes spec.json; this
script turns it into hunts/<year>/<date>-<slug>/ (hunt.yml, query.kql, query.sigma.yml),
drafts/linkedin/<id>.md and a PR description, assigns the next hunt id, and runs the checker.
Exit code 1 means the checker found errors; fix the spec and run again (the same date and
title reuse the same folder and id).

spec.json fields:
  title, severity (high|critical; lower is rejected), platforms ([defender-xdr, sentinel]), tables,
  attack {tactics, techniques}, threat {name, cves, actors}, summary, sources,
  false_positives, tuning, triage, kql, sigma ("" when none), linkedin_post (use {HUNT_URL}),
  why_today, source_item {title, url, source}
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

import yaml

from pipeline import render, validate
from pipeline.common import AUTHOR, ROOT, SCHEMA_PATH, all_hunts, load_hunt, next_hunt_id, slugify

REQUIRED = ["title", "severity", "platforms", "tables", "attack", "threat", "summary", "sources",
            "false_positives", "tuning", "triage", "kql", "sigma", "linkedin_post"]


def write_hunt(spec: dict, hunt_id: str, today: str, folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    threat = {"name": spec["threat"]["name"], "cves": spec["threat"].get("cves", []),
              "actors": spec["threat"].get("actors", [])}
    meta = {
        "id": hunt_id, "title": spec["title"], "date": today, "author": AUTHOR,
        "status": "experimental", "severity": spec["severity"], "platforms": spec["platforms"],
        "tables": spec["tables"], "attack": spec["attack"], "threat": threat,
        "summary": spec["summary"], "sources": spec["sources"],
        "false_positives": spec["false_positives"], "tuning": spec["tuning"],
        "triage": spec["triage"], "validated": "syntax",
    }
    (folder / "hunt.yml").write_text(yaml.safe_dump(meta, sort_keys=False, allow_unicode=True, width=100),
                                     encoding="utf-8")
    kql = spec["kql"].strip()
    first = kql.splitlines()[0] if kql else ""
    if hunt_id not in first:
        kql = f"// {hunt_id} {spec['title']}\n{kql}"
    (folder / "query.kql").write_text(kql + "\n", encoding="utf-8")
    sigma_path = folder / "query.sigma.yml"
    if spec.get("sigma", "").strip():
        sigma_path.write_text(spec["sigma"].strip() + "\n", encoding="utf-8")
    elif sigma_path.exists():
        sigma_path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("spec")
    parser.add_argument("--pr-body", default="pr_body.md")
    parser.add_argument("--date", default=date.today().isoformat())
    args = parser.parse_args(argv)

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    missing = [k for k in REQUIRED if k not in spec]
    if missing:
        print(f"spec.json is missing: {missing}")
        return 1
    if spec["severity"] not in ("critical", "high"):
        print(f"severity is {spec['severity']!r}: 144ThreatHunter only publishes critical and high hunts")
        return 1
    today = args.date
    folder = ROOT / "hunts" / today[:4] / f"{today}-{slugify(spec['title'], 50)}"
    existing = {h.path: h.meta["id"] for h in all_hunts()}
    hunt_id = existing.get(folder) or next_hunt_id(int(today[:4]))

    write_hunt(spec, hunt_id, today, folder)
    drafts = ROOT / "drafts" / "linkedin"
    drafts.mkdir(parents=True, exist_ok=True)
    post_path = drafts / f"{hunt_id}.md"
    post_path.write_text(spec["linkedin_post"].strip() + "\n", encoding="utf-8")

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors, warnings = validate.validate_hunt(folder, schema, links=True)
    render.main()
    post = spec["linkedin_post"].replace("{HUNT_URL}", load_hunt(folder).url).strip()
    post_path.write_text(post + "\n", encoding="utf-8")

    rel = folder.relative_to(ROOT).as_posix()
    item = spec.get("source_item") or {}
    body = [f"## {hunt_id}: {spec['title']}", ""]
    if spec.get("why_today"):
        body += [f"**Why today:** {spec['why_today']}", ""]
    if item.get("url"):
        body += [f"**Lead:** [{item.get('title', item['url'])}]({item['url']}) ({item.get('source', '')})", ""]
    body.append("**Automated checks:** " + ("FAILED, fix before merging." if errors else "passed."))
    body += [f"- error: {e}" for e in errors] + [f"- warning: {w}" for w in warnings]
    body += [
        "", "### Review checklist",
        "- [ ] Sources support every claim in the write-up",
        "- [ ] Query runs in Defender XDR or Sentinel without errors",
        "- [ ] Results are triageable (not thousands of rows in a normal tenant)",
        "- [ ] False positives and tuning are realistic",
        "- [ ] Set `validated: lab` or `production` in hunt.yml if you ran it",
        "", f"Files: `{rel}/`", "",
        "### LinkedIn draft (post this yourself after merging)", "", "```text", post, "```",
    ]
    Path(args.pr_body).write_text("\n".join(body) + "\n", encoding="utf-8")

    print(f"{hunt_id} -> {rel}")
    for e in errors:
        print(f"  error: {e}")
    for w in warnings:
        print(f"  warning: {w}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
