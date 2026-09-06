from __future__ import annotations

from pathlib import Path

import pytest

from kiyooo.config import CategoryDefinition, PredicateBlock, RouteConfig
from kiyooo.skills.loader import (
    Skill,
    SkillLoadError,
    load_skills,
    select_skills_for_category,
)

_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


def _category(category_id: str, name: str) -> CategoryDefinition:
    return CategoryDefinition.model_validate(
        dict(
            id=category_id,
            name=name,
            version=1,
            severity_base="high",
            applies_to=["http_service"],
            detect=PredicateBlock(any_of=[{"port_in": [80]}]),
            triage_hints="test",
            route=RouteConfig(assign_to="appsec", sla_days=_SLA),
        )
    )


_DEFAULT_FRONTMATTER = (
    'name: test-skill\ndescription: "a test skill"\napplies_to_categories: [exposed-database]'
)


def _write_skill(
    root: Path,
    dir_name: str,
    *,
    frontmatter: str = _DEFAULT_FRONTMATTER,
    body: str = "# Test skill\n\nSome playbook content.\n",
) -> Path:
    skill_dir = root / dir_name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")
    return skill_file


def test_load_skills_missing_root_returns_empty(tmp_path: Path) -> None:
    assert load_skills(tmp_path / "nonexistent") == []


def test_load_skills_parses_valid_skill(tmp_path: Path) -> None:
    _write_skill(tmp_path, "my-skill")
    skills = load_skills(tmp_path)
    assert len(skills) == 1
    skill = skills[0]
    assert skill.name == "test-skill"
    assert skill.description == "a test skill"
    assert skill.applies_to_categories == ["exposed-database"]
    assert "Some playbook content." in skill.body


def test_load_skills_skips_directories_without_skill_md(tmp_path: Path) -> None:
    (tmp_path / "not-a-skill").mkdir()
    (tmp_path / "not-a-skill" / "README.md").write_text("nope", encoding="utf-8")
    assert load_skills(tmp_path) == []


def test_load_skills_sorted_by_directory_name(tmp_path: Path) -> None:
    _write_skill(
        tmp_path, "z-skill", frontmatter='name: z\ndescription: "z"\napplies_to_categories: []'
    )
    _write_skill(
        tmp_path, "a-skill", frontmatter='name: a\ndescription: "a"\napplies_to_categories: []'
    )
    skills = load_skills(tmp_path)
    assert [s.name for s in skills] == ["a", "z"]


def test_missing_frontmatter_raises(tmp_path: Path) -> None:
    skill_dir = tmp_path / "broken"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("just a body, no frontmatter", encoding="utf-8")
    with pytest.raises(SkillLoadError, match="frontmatter"):
        load_skills(tmp_path)


def test_invalid_yaml_frontmatter_raises(tmp_path: Path) -> None:
    _write_skill(tmp_path, "broken", frontmatter="name: [unclosed")
    with pytest.raises(SkillLoadError, match="invalid frontmatter"):
        load_skills(tmp_path)


def test_missing_name_raises(tmp_path: Path) -> None:
    _write_skill(tmp_path, "broken", frontmatter='description: "no name here"')
    with pytest.raises(SkillLoadError, match="name"):
        load_skills(tmp_path)


def test_missing_description_raises(tmp_path: Path) -> None:
    _write_skill(tmp_path, "broken", frontmatter="name: no-description")
    with pytest.raises(SkillLoadError, match="description"):
        load_skills(tmp_path)


def test_applies_to_categories_must_be_a_list(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "broken",
        frontmatter='name: x\ndescription: "x"\napplies_to_categories: "exposed-database"',
    )
    with pytest.raises(SkillLoadError, match="applies_to_categories"):
        load_skills(tmp_path)


def test_empty_body_raises(tmp_path: Path) -> None:
    _write_skill(tmp_path, "broken", body="   \n")
    with pytest.raises(SkillLoadError, match="empty"):
        load_skills(tmp_path)


def test_select_skills_matches_explicit_applies_to_categories() -> None:
    skill = Skill(
        name="db-skill",
        description="unrelated words entirely",
        applies_to_categories=["exposed-database"],
        body="body",
        source_file="x",
    )
    selected = select_skills_for_category([skill], _category("exposed-database", "DB exposed"))
    assert [s.name for s in selected] == ["db-skill"]

    not_selected = select_skills_for_category([skill], _category("leaked-secret", "Leaked secret"))
    assert not_selected == []


def test_select_skills_relevance_fallback_matches_on_keyword_overlap() -> None:
    skill = Skill(
        name="cert-skill",
        description="playbook for handling expired certificate findings",
        applies_to_categories=[],
        body="body",
        source_file="x",
    )
    selected = select_skills_for_category([skill], _category("expired-cert", "Certificate expired"))
    assert [s.name for s in selected] == ["cert-skill"]


def test_select_skills_no_match_returns_empty() -> None:
    skill = Skill(
        name="cert-skill",
        description="playbook for handling expired certificate findings",
        applies_to_categories=[],
        body="body",
        source_file="x",
    )
    selected = select_skills_for_category([skill], _category("leaked-secret", "Leaked secret"))
    assert selected == []


def test_select_skills_respects_token_budget() -> None:
    skill_a = Skill(
        name="a",
        description="x",
        applies_to_categories=["exposed-database"],
        body="A" * 100,
        source_file="a",
    )
    skill_b = Skill(
        name="b",
        description="x",
        applies_to_categories=["exposed-database"],
        body="B" * 100,
        source_file="b",
    )
    category = _category("exposed-database", "DB exposed")
    # 10-token budget = 40 chars — enough for skill_a's full body (100 chars,
    # truncated) but nothing left for skill_b.
    selected = select_skills_for_category([skill_a, skill_b], category, token_budget=10)
    assert len(selected) == 1
    assert selected[0].name == "a"
    assert len(selected[0].body) == 40


def test_select_skills_zero_budget_selects_nothing() -> None:
    skill = Skill(
        name="a",
        description="x",
        applies_to_categories=["exposed-database"],
        body="A" * 10,
        source_file="a",
    )
    selected = select_skills_for_category(
        [skill], _category("exposed-database", "DB exposed"), token_budget=0
    )
    assert selected == []
