"""Load NyxStrike workflow skills from skills/<name>/SKILL.md (shared by REST API and MCP)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def skills_root() -> Path:
    return _SKILLS_ROOT


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text.strip()
    raw_fm = m.group(1)
    body = text[m.end():].strip()
    meta: dict[str, str] = {}
    for line in raw_fm.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        meta[key.strip()] = val.strip()
    return meta, body


def list_skill_summaries() -> list[dict[str, Any]]:
    root = skills_root()
    if not root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        skill_file = child / "SKILL.md"
        if not skill_file.is_file():
            continue
        try:
            text = skill_file.read_text(encoding="utf-8")
        except OSError:
            continue
        meta, _ = _parse_frontmatter(text)
        name = meta.get("name") or child.name
        desc = meta.get("description") or ""
        out.append({"name": name, "description": desc, "slug": child.name})
    return out


def get_skill_document(skill_slug: str) -> dict[str, Any] | None:
    slug = (skill_slug or "").strip()
    if not slug or "/" in slug or slug.startswith("."):
        return None
    skill_file = skills_root() / slug / "SKILL.md"
    if not skill_file.is_file():
        return None
    try:
        text = skill_file.read_text(encoding="utf-8")
    except OSError:
        return None
    meta, body = _parse_frontmatter(text)
    name = meta.get("name") or slug
    return {
        "slug": slug,
        "name": name,
        "description": meta.get("description") or "",
        "content": body or text.strip(),
        "raw_markdown": text,
    }
