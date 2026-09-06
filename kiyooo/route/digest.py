"""Slack daily digest: a summary of change events + new
true positives since the last run, so people aren't paged per-finding.
`build_digest` is pure; sending it is `route/sinks/slack.py`'s job.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.db.models import ChangeEvent, Finding

_MAX_LISTED_FINDINGS = 20


@dataclass(frozen=True, slots=True)
class DigestSummary:
    change_event_count: int
    true_positive_count: int
    lines: list[str] = field(default_factory=list)


def build_digest(change_events: list[ChangeEvent], routed_findings: list[Finding]) -> DigestSummary:
    lines = [
        "*kiyooo daily digest*",
        f"{len(change_events)} change event(s), {len(routed_findings)} new routed true positive(s)",
    ]
    for finding in routed_findings[:_MAX_LISTED_FINDINGS]:
        lines.append(f"- [{finding.raw_severity.value.upper()}] {finding.title}")
    if len(routed_findings) > _MAX_LISTED_FINDINGS:
        lines.append(f"...and {len(routed_findings) - _MAX_LISTED_FINDINGS} more")
    return DigestSummary(
        change_event_count=len(change_events),
        true_positive_count=len(routed_findings),
        lines=lines,
    )


def render_digest_text(summary: DigestSummary) -> str:
    return "\n".join(summary.lines)
