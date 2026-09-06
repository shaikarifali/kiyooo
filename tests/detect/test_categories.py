"""Runs the real `org-context.example` categories' `.cases.yaml` fixtures
in-process — the same logic `kiyooo categories test` (cli.py) runs, but
under pytest so a category that ships broken fails CI, not just a manual
check. Also doubles as the DoD's "≥80%"-style proof that the shipped
categories are genuinely evaluable, not just shape-valid YAML.
"""

from __future__ import annotations

from pathlib import Path

from kiyooo.config import load_org_context
from kiyooo.detect.cases import (
    build_asset,
    build_context,
    build_evidence,
    cases_path_for,
    load_cases,
)
from kiyooo.detect.evaluate import evaluate_block

ORG_CONTEXT_ROOT = Path(__file__).parent.parent.parent / "org-context.example"


def test_org_context_example_has_forty_categories() -> None:
    org_context = load_org_context(ORG_CONTEXT_ROOT)
    assert len(org_context.categories) == 40


def test_every_shipped_category_has_a_cases_file() -> None:
    org_context = load_org_context(ORG_CONTEXT_ROOT)
    missing = [
        category.id
        for category in org_context.categories.values()
        if not cases_path_for(category.source_file).exists()
    ]
    assert missing == []


def test_every_shipped_category_passes_its_own_cases() -> None:
    org_context = load_org_context(ORG_CONTEXT_ROOT)
    failures: list[str] = []
    total_cases = 0

    for category in org_context.categories.values():
        cases = load_cases(cases_path_for(category.source_file))
        for label, case_list, want_match in (
            ("should_match", cases.should_match, True),
            ("should_not_match", cases.should_not_match, False),
        ):
            for case in case_list:
                total_cases += 1
                asset = build_asset(case.asset)
                evidence = build_evidence(asset.id, case.evidence)
                ctx = build_context(case)
                matched = evaluate_block(category.detect, asset, evidence, ctx) is not None
                if matched != want_match:
                    failures.append(
                        f"{category.id}/{label}/{case.name or '(unnamed)'}: "
                        f"expected match={want_match}, got {matched}"
                    )

    assert failures == []
    assert total_cases >= 20  # sanity floor — catches an accidentally-empty fixture set
