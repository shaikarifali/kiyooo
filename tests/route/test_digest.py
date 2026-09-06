from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import (
    ChangeEvent,
    ChangeEventKind,
    Finding,
    FindingDetector,
    FindingStatus,
    Severity,
)
from kiyooo.route.digest import build_digest, render_digest_text

_NOW = datetime.now(UTC)


def _change_event() -> ChangeEvent:
    return ChangeEvent(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        kind=ChangeEventKind.ASSET_NEW,
        occurred_at=_NOW,
    )


def _finding(severity: Severity, title: str) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        category_id="exposed-database",
        raw_severity=severity,
        title=title,
        detector=FindingDetector.RULE,
        fingerprint=f"fp-{uuid.uuid4()}",
        first_seen=_NOW,
        last_seen=_NOW,
        status=FindingStatus.ROUTED,
    )


def test_empty_digest() -> None:
    summary = build_digest([], [])
    assert summary.change_event_count == 0
    assert summary.true_positive_count == 0
    assert "0 change event(s), 0 new routed true positive(s)" in render_digest_text(summary)


def test_digest_lists_findings() -> None:
    findings = [_finding(Severity.CRITICAL, "Exposed DB")]
    summary = build_digest([_change_event()], findings)
    text = render_digest_text(summary)
    assert "1 change event(s), 1 new routed true positive(s)" in text
    assert "[CRITICAL] Exposed DB" in text


def test_digest_truncates_long_lists() -> None:
    findings = [_finding(Severity.LOW, f"Finding {i}") for i in range(25)]
    summary = build_digest([], findings)
    text = render_digest_text(summary)
    assert "...and 5 more" in text
