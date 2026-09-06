from pathlib import Path

import pytest

from kiyooo.config import OrgContextError, load_org_context


def test_valid_org_context_loads(valid_org_context_root: Path) -> None:
    ctx = load_org_context(valid_org_context_root)

    assert ctx.scope.org_name == "testcorp"
    assert [t.id for t in ctx.teams.teams] == ["appsec"]
    assert [c.id for c in ctx.controls.controls] == ["test_waf"]
    assert set(ctx.categories) == {"example-category"}


def test_missing_root_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(OrgContextError):
        load_org_context(tmp_path / "does-not-exist")


def test_missing_required_field_raises(malformed_org_context_root: Path) -> None:
    with pytest.raises(OrgContextError, match="bad.yaml"):
        load_org_context(malformed_org_context_root / "missing-required-field")


def test_wrong_type_raises(malformed_org_context_root: Path) -> None:
    with pytest.raises(OrgContextError, match="bad.yaml"):
        load_org_context(malformed_org_context_root / "wrong-type")


def test_invalid_enum_value_raises(malformed_org_context_root: Path) -> None:
    with pytest.raises(OrgContextError, match="bad.yaml"):
        load_org_context(malformed_org_context_root / "invalid-enum-value")


def test_duplicate_category_id_raises(malformed_org_context_root: Path) -> None:
    with pytest.raises(OrgContextError, match="duplicate category id"):
        load_org_context(malformed_org_context_root / "duplicate-category-id")


def test_invalid_regex_raises(malformed_org_context_root: Path) -> None:
    with pytest.raises(OrgContextError, match="bad.yaml"):
        load_org_context(malformed_org_context_root / "invalid-regex")
