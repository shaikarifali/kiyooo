from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from kiyooo.config import SuppressionEntry, SuppressionsFile, load_org_context


def test_suppressions_file_defaults_empty() -> None:
    assert SuppressionsFile().suppressions == []


def test_suppressions_file_rejects_duplicate_ids() -> None:
    entry = dict(category_id="exposed-database", asset_values=["a"], reason="test")
    with pytest.raises(ValidationError, match="duplicate id"):
        SuppressionsFile(
            suppressions=[
                SuppressionEntry(id="dup", **entry),
                SuppressionEntry(id="dup", **entry),
            ]
        )


def test_suppression_entry_requires_at_least_one_asset_value() -> None:
    with pytest.raises(ValidationError):
        SuppressionEntry(id="x", category_id="exposed-database", asset_values=[], reason="test")


def test_load_org_context_defaults_suppressions_when_file_absent() -> None:
    org_context = load_org_context(Path("org-context.example"))
    assert org_context.suppressions.suppressions == []
