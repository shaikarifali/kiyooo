"""The autonomy ladder. Level is stored per category in
org-context (`CategoryDefinition.route.autonomy_level`) so promoting one is a
reviewable diff, never a runtime decision — this module only implements the
*behaviour* each level and severity combination produces; it never decides
what level a category is at.

  0 -- Shadow:  nothing sent, nothing drafted. Verdicts alone are the record.
  1 -- Approval queue: every outbound message is drafted and held.
  2 -- Auto-route low/medium; high/critical still held for approval.
  3 -- Everything auto-files.
"""

from __future__ import annotations

import enum

from kiyooo.db.models import Severity

_HELD_AT_LEVEL_2 = frozenset({Severity.HIGH, Severity.CRITICAL})


class RouteAction(enum.Enum):
    SHADOW = "shadow"
    DRAFT_FOR_APPROVAL = "draft_for_approval"
    AUTO_FILE = "auto_file"


def decide_action(autonomy_level: int, severity: Severity) -> RouteAction:
    if autonomy_level == 0:
        return RouteAction.SHADOW
    if autonomy_level == 1:
        return RouteAction.DRAFT_FOR_APPROVAL
    if autonomy_level == 2:
        return (
            RouteAction.DRAFT_FOR_APPROVAL
            if severity in _HELD_AT_LEVEL_2
            else RouteAction.AUTO_FILE
        )
    return RouteAction.AUTO_FILE
