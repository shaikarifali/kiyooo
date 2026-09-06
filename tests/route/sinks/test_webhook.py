from __future__ import annotations

from datetime import UTC, datetime

from kiyooo.route.sinks.webhook import build_payload


def test_build_payload_create() -> None:
    due = datetime(2026, 1, 1, tzinfo=UTC)
    payload = build_payload(
        action="create",
        subject="[HIGH] X",
        body="body",
        assignee="dev@example.com",
        cc=["mgr@example.com"],
        sla_due_at=due,
        external_key=None,
    )
    assert payload["action"] == "create"
    assert payload["assignee"] == "dev@example.com"
    assert payload["cc"] == ["mgr@example.com"]
    assert payload["sla_due_at"] == due.isoformat()
    assert payload["external_key"] is None


def test_build_payload_reopen_has_no_sla_or_assignee() -> None:
    payload = build_payload(
        action="reopen",
        subject=None,
        body="body",
        assignee=None,
        cc=[],
        sla_due_at=None,
        external_key="ext-1",
    )
    assert payload["action"] == "reopen"
    assert payload["external_key"] == "ext-1"
    assert payload["sla_due_at"] is None
