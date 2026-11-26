"""Render generated files from hunt metadata.

- hunts/<year>/<slug>/README.md   the write-up for each hunt
- index/by-technique.md, index/by-platform.md
- feed/hunts.json                 machine-readable feed (for 144company.com and others)
- README.md                       the "Latest hunts" table between marker comments

Usage: python -m pipeline.render
"""
from __future__ import annotations

from collections import defaultdict

from pipeline.common import REPO_URL, ROOT, Hunt, all_hunts, write_json

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"
PLATFORM_NAMES = {"defender-xdr": "Microsoft Defender XDR", "sentinel": "Microsoft Sentinel"}
LATEST_START = "<!-- latest-hunts:start -->"
LATEST_END = "<!-- latest-hunts:end -->"


def technique_link(tech: str) -> str:
    return f"[{tech}]({ATTACK_URL.format(tech.replace('.', '/'))})"


def hunt_readme(h: Hunt) -> str:
    m = h.meta
    lines = [
        f"# {m['id']}: {m['title']}",
        "",
        f"**Date:** {m['date']} · **Severity:** {m['severity']} · **Status:** {m['status']} · "
        f"**Validated:** {m['validated']}",
        "",
        f"**Platforms:** {', '.join(PLATFORM_NAMES.get(p, p) for p in m['platforms'])} · "
        f"**Tables:** {', '.join(f'`{t}`' for t in m['tables'])}",
        "",
        f"**MITRE ATT&CK:** {', '.join(technique_link(t) for t in m['attack']['techniques'])}",
        "",
        "## Why hunt for this",
        "",
        m["summary"].strip(),
        "",
    ]
    threat = m["threat"]
    if threat.get("cves") or threat.get("actors"):
        lines += ["## Threat", "", f"- **Name:** {threat['name']}"]
        if threat.get("cves"):
            lines.append(f"- **CVEs:** {', '.join(threat['cves'])}")
        if threat.get("actors"):
            lines.append(f"- **Actors:** {', '.join(threat['actors'])}")
        lines.append("")
    lines += ["## Query (KQL)", "", "```kql", h.kql.rstrip(), "```", ""]
    if h.sigma:
        lines += ["A portable [Sigma version](query.sigma.yml) is included for other SIEMs.", ""]
    lines += ["## When it fires", ""]
    lines += [f"{i}. {step}" for i, step in enumerate(m["triage"], 1)]
    lines += ["", "## Known false positives", ""]
    lines += [f"- {fp}" for fp in m["false_positives"]]
    lines += ["", "## Tuning", "", m["tuning"].strip(), "", "## Sources", ""]
    lines += [f"- <{s}>" for s in m["sources"]]
    lines += [
        "",
        "---",
        f"*Validation level `{m['validated']}`: `syntax` means the query passed automated checks "
        "but has not been run against live data. Test in your own environment before relying on it.*",
        "",
    ]
    return "\n".join(lines)


def render_indexes(hunts: list[Hunt]) -> None:
    by_tech: dict[str, list[Hunt]] = defaultdict(list)
    by_platform: dict[str, list[Hunt]] = defaultdict(list)
    for h in hunts:
        for t in h.meta["attack"]["techniques"]:
            by_tech[t].append(h)
        for p in h.meta["platforms"]:
            by_platform[p].append(h)

    def row(h: Hunt) -> str:
        rel = h.path.relative_to(ROOT).as_posix()
        return f"| {h.meta['date']} | [{h.meta['id']}](../{rel}) | {h.meta['title']} | {h.meta['severity']} |"

    out = ["# Hunts by MITRE ATT&CK technique", ""]
    for tech in sorted(by_tech):
        out += [f"## {technique_link(tech)}", "", "| Date | ID | Hunt | Severity |", "| --- | --- | --- | --- |"]
        out += [row(h) for h in sorted(by_tech[tech], key=lambda x: x.meta["date"], reverse=True)]
        out.append("")
    (ROOT / "index" / "by-technique.md").write_text("\n".join(out), encoding="utf-8")

    out = ["# Hunts by platform", ""]
    for plat in sorted(by_platform):
        out += [f"## {PLATFORM_NAMES.get(plat, plat)}", "", "| Date | ID | Hunt | Severity |", "| --- | --- | --- | --- |"]
        out += [row(h) for h in sorted(by_platform[plat], key=lambda x: x.meta["date"], reverse=True)]
        out.append("")
    (ROOT / "index" / "by-platform.md").write_text("\n".join(out), encoding="utf-8")


def render_feed(hunts: list[Hunt]) -> None:
    items = []
    for h in sorted(hunts, key=lambda x: (x.meta["date"], x.meta["id"]), reverse=True):
        m = h.meta
        items.append({
            "id": m["id"], "title": m["title"], "date": m["date"], "severity": m["severity"],
            "status": m["status"], "validated": m["validated"], "platforms": m["platforms"],
            "techniques": m["attack"]["techniques"], "cves": m["threat"].get("cves", []),
            "summary": m["summary"].strip(), "kql": h.kql, "url": h.url,
        })
    write_json(ROOT / "feed" / "hunts.json", {"source": REPO_URL, "hunts": items})


def render_root_readme(hunts: list[Hunt], limit: int = 10) -> None:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    rows = ["| Date | ID | Hunt | ATT&CK | Severity |", "| --- | --- | --- | --- | --- |"]
    for h in sorted(hunts, key=lambda x: (x.meta["date"], x.meta["id"]), reverse=True)[:limit]:
        rel = h.path.relative_to(ROOT).as_posix()
        techs = ", ".join(h.meta["attack"]["techniques"][:3])
        rows.append(f"| {h.meta['date']} | [{h.meta['id']}]({rel}) | {h.meta['title']} | {techs} | {h.meta['severity']} |")
    start, end = text.index(LATEST_START), text.index(LATEST_END)
    text = text[: start + len(LATEST_START)] + "\n" + "\n".join(rows) + "\n" + text[end:]
    readme.write_text(text, encoding="utf-8")


def main() -> None:
    hunts = all_hunts()
    for h in hunts:
        (h.path / "README.md").write_text(hunt_readme(h), encoding="utf-8")
    render_indexes(hunts)
    render_feed(hunts)
    render_root_readme(hunts)
    print(f"rendered {len(hunts)} hunts")


if __name__ == "__main__":
    main()
