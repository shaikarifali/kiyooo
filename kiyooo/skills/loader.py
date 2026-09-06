"""skills/loader.py — Stage 9: org-specific playbooks injected
into triage on demand. Reads `org-context/skills/*/SKILL.md` (Anthropic
skills format: YAML frontmatter — `name`, `description`,
`applies_to_categories` — then a markdown body) and selects which ones
apply to a given category, capping total injected tokens per bundle.

A skill is a knowledge injection only here — the body text a category's
`triage_hints` couldn't hold. The design also floats letting a skill ship
executable helpers (`scripts/`) exposed as extra verification tools; that
is deliberately not implemented — `verify/safety.py`'s `ALLOWED_TOOLS` is a
closed, hardcoded set of exactly six reviewed tools by design ("the model
cannot name a tool that isn't one of these regardless of what it asks
for"), and letting arbitrary org-authored skill scripts extend that
allowlist is a scope-enforcement decision, not a content-loading one — see
CLAUDE.md's "if a task would touch ... the verification executor ...
prefer a clarifying question over an assumption."

Malformed frontmatter is a hard failure, same as every other org-context
file (CLAUDE.md: "fail loudly on a malformed category — never silently
skip one"). A missing `skills/` directory is not an error — most orgs
won't have any yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from kiyooo.config import CategoryDefinition

_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n?(.*)", re.DOTALL)
_CHARS_PER_TOKEN = 4
_DEFAULT_SKILL_TOKEN_BUDGET = 2_000
_MIN_RELEVANCE_WORD_LEN = 4

# Words too generic to a security-scanning vocabulary to count as a
# relevance signal on their own ("exposed" appears in half this project's
# shipped category ids) — without this, the relevance fallback matches
# almost everything to almost everything.
_RELEVANCE_STOPWORDS = frozenset(
    {
        # Domain-generic — appear in most category names/skill descriptions
        # in a security-scanning tool, so they carry no discriminating signal.
        "expose",
        "exposed",
        "exposure",
        "finding",
        "findings",
        "public",
        "publicly",
        "content",
        "actually",
        "security",
        "assess",
        "assessment",
        "real",
        "never",
        # Ordinary English connectives that show up in full-sentence
        # category names ("Database service reachable from the internet").
        "which",
        "their",
        "these",
        "those",
        "with",
        "that",
        "this",
        "from",
        "have",
        "will",
        "your",
        "when",
        "then",
        "than",
        "into",
        "onto",
        "over",
        "some",
        "such",
        "only",
        "also",
        "more",
        "most",
        "much",
        "each",
        "both",
        "here",
        "there",
        "what",
        "were",
        "been",
        "being",
        "does",
        "done",
    }
)


class SkillLoadError(Exception):
    """A malformed SKILL.md — never silently skipped."""


@dataclass(frozen=True, slots=True)
class Skill:
    name: str
    description: str
    applies_to_categories: list[str]
    body: str
    source_file: str


@dataclass(frozen=True, slots=True)
class SelectedSkill:
    name: str
    body: str


def _parse_skill_md(text: str, *, source_file: str) -> Skill:
    match = _FRONTMATTER_RE.match(text)
    if match is None:
        raise SkillLoadError(f"{source_file}: missing YAML frontmatter (expected '---' block)")
    frontmatter_raw, body = match.groups()

    try:
        frontmatter = yaml.safe_load(frontmatter_raw) or {}
    except yaml.YAMLError as exc:
        raise SkillLoadError(f"{source_file}: invalid frontmatter YAML: {exc}") from exc
    if not isinstance(frontmatter, dict):
        raise SkillLoadError(f"{source_file}: frontmatter must be a YAML mapping")

    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if not name or not isinstance(name, str):
        raise SkillLoadError(f"{source_file}: frontmatter requires a non-empty 'name'")
    if not description or not isinstance(description, str):
        raise SkillLoadError(f"{source_file}: frontmatter requires a non-empty 'description'")

    applies_to = frontmatter.get("applies_to_categories", [])
    if not isinstance(applies_to, list) or not all(isinstance(c, str) for c in applies_to):
        raise SkillLoadError(f"{source_file}: 'applies_to_categories' must be a list of strings")

    if not body.strip():
        raise SkillLoadError(f"{source_file}: skill body is empty")

    return Skill(
        name=name,
        description=description,
        applies_to_categories=list(applies_to),
        body=body.strip(),
        source_file=source_file,
    )


def load_skills(root: Path) -> list[Skill]:
    """Reads every `<root>/*/SKILL.md`, sorted by directory name for a
    stable, diffable order. `root` not existing means "no skills yet," not
    an error.
    """
    if not root.is_dir():
        return []
    skills: list[Skill] = []
    for skill_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            continue
        skills.append(
            _parse_skill_md(skill_file.read_text(encoding="utf-8"), source_file=str(skill_file))
        )
    return skills


def _relevance_match(skill: Skill, category: CategoryDefinition) -> bool:
    """Fallback for a skill with no explicit `applies_to_categories` match:
    a plain keyword overlap between the skill's description and the
    category's id/name — not a model call, since the model gets no say
    over what context it's shown.
    """
    haystack = f"{category.id} {category.name}".lower()
    words = {
        w
        for w in re.findall(r"[a-z0-9]+", skill.description.lower())
        if len(w) >= _MIN_RELEVANCE_WORD_LEN and w not in _RELEVANCE_STOPWORDS
    }
    return any(w in haystack for w in words)


def select_skills_for_category(
    skills: list[Skill],
    category: CategoryDefinition,
    *,
    token_budget: int = _DEFAULT_SKILL_TOKEN_BUDGET,
) -> list[SelectedSkill]:
    matched = [
        skill
        for skill in skills
        if category.id in skill.applies_to_categories or _relevance_match(skill, category)
    ]

    selected: list[SelectedSkill] = []
    remaining_chars = token_budget * _CHARS_PER_TOKEN
    for skill in matched:
        if remaining_chars <= 0:
            break
        body = skill.body[:remaining_chars]
        selected.append(SelectedSkill(name=skill.name, body=body))
        remaining_chars -= len(body)
    return selected
