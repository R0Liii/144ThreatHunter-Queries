"""Validate hunts: metadata schema, KQL lint, Sigma parse, cross-checks, source links.

Usage:
    python -m pipeline.validate                 # all hunts
    python -m pipeline.validate hunts/2026/x    # specific hunt folders
    python -m pipeline.validate --check-links   # also confirm every source URL resolves

Exit code 1 when any hunt has an error. Warnings never fail the run.

The KQL check is a lint, not a full parser: it catches unbalanced brackets, unknown
tables, a missing time filter and a header that doesn't match the metadata. Testing in a
real Sentinel or Defender tenant is still the reviewer's job before merge.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import jsonschema

from pipeline.common import ROOT, SCHEMA_PATH, all_hunt_dirs, load_hunt

# Advanced hunting tables in Defender XDR plus common Sentinel tables.
KNOWN_TABLES = {
    # Defender for Endpoint
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents",
    "DeviceLogonEvents", "DeviceImageLoadEvents", "DeviceEvents", "DeviceInfo",
    "DeviceNetworkInfo", "DeviceFileCertificateInfo", "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareInventory",
    # Defender for Office 365 / Identity / Cloud Apps
    "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "EmailPostDeliveryEvents", "UrlClickEvents",
    "IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents", "IdentityInfo",
    "CloudAppEvents", "AlertInfo", "AlertEvidence", "BehaviorInfo", "BehaviorEntities",
    # Sentinel / Log Analytics
    "SigninLogs", "AADNonInteractiveUserSignInLogs", "AuditLogs", "AzureActivity",
    "OfficeActivity", "SecurityEvent", "Syslog", "CommonSecurityLog", "W3CIISLog",
    "AzureDiagnostics", "SecurityAlert", "SecurityIncident", "ThreatIntelligenceIndicator",
    "DnsEvents", "Event", "Heartbeat",
}
URL_RE = re.compile(r"https?://[^\s)\"'>\]]+", re.IGNORECASE)


def research_only_domains() -> list[str]:
    import yaml

    policy = yaml.safe_load((ROOT / "pipeline" / "source_policy.yml").read_text(encoding="utf-8"))
    return [d.lower() for d in policy.get("research_only") or []]


def _host_matches(text: str, domains: list[str]) -> list[str]:
    hits = []
    lowered = text.lower()
    for d in domains:
        if re.search(rf"(^|[^a-z0-9-]){re.escape(d)}\b", lowered):
            hits.append(d)
    return hits


def check_source_policy(path: Path, meta: dict) -> list[str]:
    """Research-only sources may never appear in published files."""
    errors = []
    domains = research_only_domains()
    texts = {f.name: f.read_text(encoding="utf-8") for f in path.iterdir() if f.is_file()}
    draft = ROOT / "drafts" / "linkedin" / f"{meta.get('id')}.md"
    if draft.exists():
        texts[f"drafts/linkedin/{draft.name}"] = draft.read_text(encoding="utf-8")
    for name, text in texts.items():
        for d in _host_matches(text, domains):
            errors.append(f"{name} mentions research-only source {d}; it may be a lead but must not be published")
    if not meta.get("sources"):
        errors.append("every hunt must link at least one source")
    return errors


TIME_FILTER = re.compile(r"\b(Timestamp|TimeGenerated)\s*(>|>=|between)\s*", re.IGNORECASE)


def _strip_kql(text: str) -> str:
    """Remove comments and string literals so bracket counting is reliable."""
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r'@?"(?:[^"\\\n]|\\.)*"', '""', text)
    text = re.sub(r"@?'(?:[^'\\\n]|\\.)*'", "''", text)
    return text


def lint_kql(kql: str, meta: dict) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    code = _strip_kql(kql)
    for open_c, close_c in ("()", "[]", "{}"):
        if code.count(open_c) != code.count(close_c):
            errors.append(f"KQL: unbalanced {open_c}{close_c} ({code.count(open_c)} vs {code.count(close_c)})")
    if code.count('"') % 2 or code.count("'") % 2:
        errors.append("KQL: unterminated string literal")

    statements = [s.strip() for s in code.split(";") if s.strip()]
    if not statements:
        errors.append("KQL: query is empty")
        return errors, warnings
    body = [s for s in statements if not s.startswith("let ")]
    if not body:
        errors.append("KQL: only let statements, no tabular expression")
        return errors, warnings
    first_token = re.match(r"[A-Za-z_][A-Za-z0-9_]*", body[-1])
    referenced = set(re.findall(r"\b([A-Z][A-Za-z0-9]+)\b\s*(?:\n\s*)?\|", code))
    referenced |= {first_token.group(0)} if first_token else set()
    tables = referenced & KNOWN_TABLES
    if not tables:
        errors.append("KQL: no known table referenced (see KNOWN_TABLES in pipeline/validate.py)")
    missing = tables - set(meta.get("tables", []))
    if missing:
        errors.append(f"KQL uses tables not listed in hunt.yml tables: {sorted(missing)}")
    if not TIME_FILTER.search(code):
        warnings.append("KQL: no Timestamp/TimeGenerated filter; the query may scan the full retention")
    if meta.get("id") and meta["id"] not in kql.splitlines()[0]:
        errors.append(f"KQL: first line must be a comment starting with the hunt id {meta['id']}")
    for tech in meta.get("attack", {}).get("techniques", []):
        if tech not in kql:
            warnings.append(f"KQL header does not mention technique {tech}")
    return errors, warnings


def lint_sigma(sigma: str, meta: dict) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        warnings.append("pySigma not installed; Sigma rule not parsed")
        return errors, warnings
    try:
        collection = SigmaCollection.from_yaml(sigma)
        collection.resolve_rule_references()
        if not collection.rules:
            errors.append("Sigma: no rule found")
        for err in getattr(collection, "errors", []) or []:
            errors.append(f"Sigma: {err}")
        for rule in collection.rules:
            tags = {str(t).lower() for t in rule.tags}
            for tech in meta.get("attack", {}).get("techniques", []):
                if f"attack.{tech.lower()}" not in tags:
                    warnings.append(f"Sigma tags missing attack.{tech.lower()}")
    except Exception as exc:  # pySigma raises many specific error types
        errors.append(f"Sigma: {type(exc).__name__}: {exc}")
    return errors, warnings


def check_links(urls: list[str]) -> list[str]:
    import requests

    problems = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=20, allow_redirects=True,
                                headers={"User-Agent": "144ThreatHunter-validator"})
            if resp.status_code >= 400:
                problems.append(f"source {url} returned HTTP {resp.status_code}")
        except requests.RequestException as exc:
            problems.append(f"source {url} unreachable: {type(exc).__name__}")
    return problems


def validate_hunt(path: Path, schema: dict, links: bool) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    for required in ("hunt.yml", "query.kql"):
        if not (path / required).exists():
            return [f"missing {required}"], []
    hunt = load_hunt(path)
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(hunt.meta), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "(root)"
        errors.append(f"hunt.yml {loc}: {err.message}")
    if not path.name.startswith(str(hunt.meta.get("date", ""))):
        errors.append("folder name must start with the hunt date (YYYY-MM-DD-)")
    e, w = lint_kql(hunt.kql, hunt.meta)
    errors += e
    warnings += w
    if hunt.sigma:
        e, w = lint_sigma(hunt.sigma, hunt.meta)
        errors += e
        warnings += w
    errors += check_source_policy(path, hunt.meta)
    if links:
        errors += check_links(hunt.meta.get("sources", []))
    return errors, warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="hunt folders (default: all)")
    parser.add_argument("--check-links", action="store_true")
    parser.add_argument("--json", help="write results to this JSON file")
    args = parser.parse_args(argv)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    paths = [Path(p).resolve() for p in args.paths] or all_hunt_dirs()
    ids: dict[str, Path] = {}
    results, failed = {}, False
    for path in paths:
        errors, warnings = validate_hunt(path, schema, args.check_links)
        try:
            hid = load_hunt(path).meta.get("id")
            if hid in ids and ids[hid] != path:
                errors.append(f"duplicate id {hid} (also in {ids[hid].relative_to(ROOT)})")
            ids[hid] = path
        except Exception:
            pass
        rel = path.relative_to(ROOT).as_posix()
        results[rel] = {"errors": errors, "warnings": warnings}
        status = "FAIL" if errors else "ok"
        print(f"[{status}] {rel}")
        for msg in errors:
            print(f"    error: {msg}")
        for msg in warnings:
            print(f"    warning: {msg}")
        failed |= bool(errors)
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
