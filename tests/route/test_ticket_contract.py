from __future__ import annotations

from pathlib import Path

import pytest

from kiyooo.route.ticket_contract import (
    REQUIRED_BLOCKS,
    TicketContractViolation,
    build_ticket_subject,
    dummy_context,
    lint_ticket_body,
    render_ticket,
    render_ticket_body,
)

_COMPLETE_BODY = "\n\n".join(
    f"## {block.title()}\ncontent for {block}" for block in REQUIRED_BLOCKS
)


def test_lint_passes_when_all_blocks_present() -> None:
    assert lint_ticket_body(_COMPLETE_BODY) == []


def test_lint_reports_missing_blocks() -> None:
    body = "## What is exposed\nsomething\n\n## What to do\nfix it"
    missing = lint_ticket_body(body)
    assert "why we believe this is real" in missing
    assert "how to verify the fix" in missing
    assert "what is exposed" not in missing
    assert "what to do" not in missing


def test_lint_reports_empty_block_as_missing() -> None:
    body = _COMPLETE_BODY.replace("content for what to do", "")
    assert "what to do" in lint_ticket_body(body)


def test_default_template_renders_and_satisfies_the_contract() -> None:
    body = render_ticket_body(dummy_context())
    assert lint_ticket_body(body) == []


def test_render_ticket_raises_on_contract_violation(tmp_path: Path) -> None:
    broken = tmp_path / "broken.md.j2"
    broken.write_text("## What is exposed\nonly one block, missing the other five.\n")

    with pytest.raises(TicketContractViolation) as exc_info:
        render_ticket(dummy_context(), subject="x", template_path=broken)
    assert "what to do" in exc_info.value.missing


def test_render_ticket_happy_path() -> None:
    rendered = render_ticket(
        dummy_context(),
        subject=build_ticket_subject(severity="high", category_name="X", asset_value="a.b.c"),
    )
    assert rendered.subject == "[HIGH] X — a.b.c"
    assert lint_ticket_body(rendered.body) == []


def test_build_ticket_subject_uppercases_severity() -> None:
    subject = build_ticket_subject(
        severity="critical", category_name="Leaked secret", asset_value="repo/x"
    )
    assert subject == "[CRITICAL] Leaked secret — repo/x"
