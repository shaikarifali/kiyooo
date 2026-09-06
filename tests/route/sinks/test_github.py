from __future__ import annotations

from kiyooo.route.sinks.github import build_create_payload


def test_build_create_payload_with_assignee() -> None:
    payload = build_create_payload(subject="[HIGH] X", body="body", assignee="dev@example.com")
    assert payload == {"title": "[HIGH] X", "body": "body", "assignees": ["dev@example.com"]}


def test_build_create_payload_without_assignee_omits_key() -> None:
    payload = build_create_payload(subject="[HIGH] X", body="body", assignee=None)
    assert "assignees" not in payload
