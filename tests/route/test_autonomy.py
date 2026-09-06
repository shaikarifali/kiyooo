from __future__ import annotations

from kiyooo.db.models import Severity
from kiyooo.route.autonomy import RouteAction, decide_action


def test_level_0_is_always_shadow() -> None:
    assert decide_action(0, Severity.CRITICAL) == RouteAction.SHADOW
    assert decide_action(0, Severity.INFO) == RouteAction.SHADOW


def test_level_1_always_drafts() -> None:
    assert decide_action(1, Severity.CRITICAL) == RouteAction.DRAFT_FOR_APPROVAL
    assert decide_action(1, Severity.LOW) == RouteAction.DRAFT_FOR_APPROVAL


def test_level_2_holds_high_and_critical_but_auto_files_the_rest() -> None:
    assert decide_action(2, Severity.CRITICAL) == RouteAction.DRAFT_FOR_APPROVAL
    assert decide_action(2, Severity.HIGH) == RouteAction.DRAFT_FOR_APPROVAL
    assert decide_action(2, Severity.MEDIUM) == RouteAction.AUTO_FILE
    assert decide_action(2, Severity.LOW) == RouteAction.AUTO_FILE
    assert decide_action(2, Severity.INFO) == RouteAction.AUTO_FILE


def test_level_3_always_auto_files() -> None:
    assert decide_action(3, Severity.CRITICAL) == RouteAction.AUTO_FILE
    assert decide_action(3, Severity.INFO) == RouteAction.AUTO_FILE
