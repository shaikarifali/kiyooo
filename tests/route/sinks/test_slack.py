from __future__ import annotations

from kiyooo.route.sinks.slack import build_message


def test_build_message_with_channel_and_subject() -> None:
    payload = build_message(channel="#appsec-triage", subject="Heads up", body="details here")
    assert payload["text"] == "[#appsec-triage] *Heads up*\ndetails here"


def test_build_message_without_channel_or_subject() -> None:
    payload = build_message(channel=None, subject="", body="just the body")
    assert payload["text"] == "just the body"
