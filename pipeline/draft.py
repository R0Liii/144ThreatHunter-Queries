"""Drafter: research the picked threat and write a complete hunt plus a LinkedIn draft.

Usage: python -m pipeline.draft --pick pick.json [--pr-body pr_body.md]

Writes hunts/<year>/<date>-<slug>/ (hunt.yml, query.kql, query.sigma.yml), renders the README,
writes drafts/linkedin/<id>.md, then validates. On validation errors it gives the model one
chance to fix them in the same conversation. Whatever the outcome, a human reviews the PR.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

import yaml

from pipeline import render, validate
from pipeline.common import AUTHOR, ROOT, SCHEMA_PATH, load_hunt, next_hunt_id, read_json, slugify
from pipeline.llm import ask_json, cited_urls

SYSTEM = """You are a senior threat hunter writing for 144ThreatHunter, a public GitHub repo of
threat hunting queries for Microsoft Defender XDR advanced hunting and Microsoft Sentinel.
Your name is not on the work; Jose's is, so accuracy matters more than speed.

Research first. Use web_fetch on the source URL you are given, then web_search and web_fetch for
the vendor advisory, CISA advisory, and any technical write-up with indicators or behavior.
Rules:
- Every factual claim must come from a page you fetched in this session. List only fetched
  pages in `sources`, primary sources first. Never invent CVEs, actors, file names or IOCs.
- Hunt for behavior (process lineage, command lines, file writes, network patterns, sign-ins)
  rather than only hashes or IPs, which go stale within days. Indicators are fine as an extra
  `let` list when a source publishes them.
- KQL targets Defender XDR advanced hunting (column `Timestamp`); the header notes that Sentinel
  uses `TimeGenerated`. Use only real tables and columns. Include a time filter, use `has`/`in~`
  over `contains` where possible, and end with summarize or project so results are triageable.
- The first KQL line is `// <id> <title>`, followed by comment lines for platform, the Sentinel
  note, and `MITRE ATT&CK: <technique ids>`.
- The Sigma rule (optional; empty string when the logic does not translate) must be valid Sigma
  with attack.* tags for each technique.
- False positives and tuning must be concrete, not generic.
- Do not copy detection logic verbatim from vendors; write your own and link theirs.
- The LinkedIn post: under 1,300 characters, first line is a hook naming the threat, then 3 short
  lines on what it is, what the hunt looks for, and who should run it. End with the placeholder
  {HUNT_URL} on its own line and 3 to 5 hashtags. Plain, confident, no hype, no emoji.
- `validated` is always "syntax"; a human upgrades it after testing."""


def draft_schema() -> dict:
    """Structured-output schema: hunt metadata fields plus query bodies and the post."""
    str_list = {"type": "array", "items": {"type": "string"}}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["title", "severity", "platforms", "tables", "attack", "threat", "summary",
                     "sources", "false_positives", "tuning", "triage", "kql", "sigma", "linkedin_post"],
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "platforms": {"type": "array", "items": {"type": "string", "enum": ["defender-xdr", "sentinel"]}},
            "tables": str_list,
            "attack": {
                "type": "object", "additionalProperties": False,
                "required": ["tactics", "techniques"],
                "properties": {"tactics": str_list, "techniques": str_list},
            },
            "threat": {
                "type": "object", "additionalProperties": False,
                "required": ["name", "cves", "actors"],
                "properties": {"name": {"type": "string"}, "cves": str_list, "actors": str_list},
            },
            "summary": {"type": "string"},
            "sources": str_list,
            "false_positives": str_list,
            "tuning": {"type": "string"},
            "triage": str_list,
            "kql": {"type": "string"},
            "sigma": {"type": "string"},
            "linkedin_post": {"type": "string"},
        },
    }


def write_hunt(out: dict, hunt_id: str, today: str, folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    meta = {
        "id": hunt_id, "title": out["title"], "date": today, "author": AUTHOR,
        "status": "experimental", "severity": out["severity"], "platforms": out["platforms"],
        "tables": out["tables"], "attack": out["attack"], "threat": out["threat"],
        "summary": out["summary"], "sources": out["sources"],
        "false_positives": out["false_positives"], "tuning": out["tuning"],
        "triage": out["triage"], "validated": "syntax",
    }
    (folder / "hunt.yml").write_text(yaml.safe_dump(meta, sort_keys=False, allow_unicode=True, width=100),
                                     encoding="utf-8")
    (folder / "query.kql").write_text(out["kql"].strip() + "\n", encoding="utf-8")
    sigma_path = folder / "query.sigma.yml"
    if out["sigma"].strip():
        sigma_path.write_text(out["sigma"].strip() + "\n", encoding="utf-8")
    elif sigma_path.exists():
        sigma_path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pick", default="pick.json")
    parser.add_argument("--pr-body", default="pr_body.md")
    args = parser.parse_args(argv)

    pick = read_json(Path(args.pick), None)
    if not pick:
        raise SystemExit("no pick file")
    item = pick["item"]
    today = date.today().isoformat()
    hunt_id = next_hunt_id(date.today().year)

    prompt = (
        f"Hunt id: {hunt_id}\nDate: {today}\n\n"
        f"Today's threat: {item['title']}\nSource: {item['source']}\nURL: {item['url']}\n"
        f"CVEs: {', '.join(item.get('cves', [])) or 'none listed'}\n"
        f"Feed summary: {item['summary'][:800]}\n\n"
        f"Triage note: {pick['reason']}\nSuggested angle: {pick['hunt_angle']}\n\n"
        "Research it and write the hunt."
    )
    out, history = ask_json(SYSTEM, [{"role": "user", "content": prompt}], draft_schema(), web=True)

    folder = ROOT / "hunts" / today[:4] / f"{today}-{slugify(out['title'], 50)}"
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors: list[str] = []
    warnings: list[str] = []
    for attempt in range(2):
        write_hunt(out, hunt_id, today, folder)
        errors, warnings = validate.validate_hunt(folder, schema, links=False)
        fetched = cited_urls(history) | {item["url"]}
        unfetched = [s for s in out["sources"] if s not in fetched]
        if unfetched:
            errors.append(f"sources not fetched or searched in this session: {unfetched}")
        if not errors or attempt == 1:
            break
        history.append({"role": "user", "content": (
            "The validator found these problems. Fix them and return the full hunt again:\n- "
            + "\n- ".join(errors))})
        out, history = ask_json(SYSTEM, history, draft_schema(), web=True)

    render.main()
    hunt = load_hunt(folder)
    post = out["linkedin_post"].replace("{HUNT_URL}", hunt.url)
    drafts = ROOT / "drafts" / "linkedin"
    drafts.mkdir(parents=True, exist_ok=True)
    (drafts / f"{hunt_id}.md").write_text(post.strip() + "\n", encoding="utf-8")

    rel = folder.relative_to(ROOT).as_posix()
    status = "Validation failed; fix before merging." if errors else "Passed automated checks."
    body = [
        f"## {hunt_id}: {out['title']}", "",
        f"**Why today:** {pick['reason']}", "",
        f"**Source item:** [{item['title']}]({item['url']}) ({item['source']})", "",
        f"**Automated checks:** {status}",
    ]
    body += [f"- error: {e}" for e in errors] + [f"- warning: {w}" for w in warnings]
    body += [
        "", "### Review checklist",
        "- [ ] Sources support every claim in the write-up",
        "- [ ] Query runs in Defender XDR or Sentinel without errors",
        "- [ ] Results are triageable (not thousands of rows in a normal tenant)",
        "- [ ] False positives and tuning are realistic",
        "- [ ] Set `validated: lab` or `production` in hunt.yml if you ran it",
        "", f"Files: `{rel}/`", "",
        "### LinkedIn draft (post this yourself after merging)", "", "```text", post.strip(), "```",
    ]
    Path(args.pr_body).write_text("\n".join(body) + "\n", encoding="utf-8")
    print(f"drafted {hunt_id} in {rel} ({'with errors' if errors else 'clean'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
