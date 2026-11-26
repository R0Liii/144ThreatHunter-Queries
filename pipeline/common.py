"""Shared helpers: paths, loading hunts, and small utilities."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
HUNTS_DIR = ROOT / "hunts"
SCHEMA_PATH = ROOT / "schema" / "hunt.schema.json"
# GitHub Actions sets GITHUB_REPOSITORY (owner/name), so a repo rename needs no code change.
REPO_URL = "https://github.com/" + os.environ.get("GITHUB_REPOSITORY", "R0Liii/144ThreatHunter-Queries")
AUTHOR = "Jose (R0Liii)"


@dataclass
class Hunt:
    path: Path
    meta: dict
    kql: str
    sigma: str | None

    @property
    def slug(self) -> str:
        return self.path.name

    @property
    def url(self) -> str:
        return f"{REPO_URL}/tree/main/{self.path.relative_to(ROOT).as_posix()}"


def load_hunt(path: Path) -> Hunt:
    meta = yaml.safe_load((path / "hunt.yml").read_text(encoding="utf-8"))
    kql = (path / "query.kql").read_text(encoding="utf-8")
    sigma_path = path / "query.sigma.yml"
    sigma = sigma_path.read_text(encoding="utf-8") if sigma_path.exists() else None
    return Hunt(path=path, meta=meta, kql=kql, sigma=sigma)


def all_hunt_dirs() -> list[Path]:
    return sorted(p.parent for p in HUNTS_DIR.glob("*/*/hunt.yml"))


def all_hunts() -> list[Hunt]:
    return [load_hunt(p) for p in all_hunt_dirs()]


def next_hunt_id(year: int) -> str:
    nums = [
        int(h.meta["id"].split("-")[2])
        for h in all_hunts()
        if h.meta.get("id", "").startswith(f"TH-{year}-")
    ]
    return f"TH-{year}-{(max(nums) + 1 if nums else 1):04d}"


def slugify(text: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:max_len].rstrip("-")


def read_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
