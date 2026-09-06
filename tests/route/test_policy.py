from __future__ import annotations

from datetime import UTC, datetime

from kiyooo.config import CategoryDefinition, PredicateBlock, RouteConfig, TeamDefinition, TeamsFile
from kiyooo.db.models import OwnershipSource, OwnerType
from kiyooo.enrich.ownership.merge import MergeOutcome, MergeResult, OwnershipCandidate
from kiyooo.route.policy import resolve_route

_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}
_NOW = datetime.now(UTC)


def _category(assign_to: str, cc: list[str], **route_overrides: object) -> CategoryDefinition:
    route_kwargs: dict[str, object] = dict(assign_to=assign_to, cc=cc, sla_days=_SLA)
    route_kwargs.update(route_overrides)
    route = RouteConfig.model_validate(route_kwargs)
    return CategoryDefinition.model_validate(
        dict(
            id="exposed-nonprod-to-internet",
            name="Non-prod exposed",
            version=1,
            severity_base="high",
            applies_to=["http_service"],
            detect=PredicateBlock(any_of=[{"port_in": [80]}]),
            triage_hints="test",
            route=route,
        )
    )


def _teams() -> TeamsFile:
    return TeamsFile(
        teams=[
            TeamDefinition(
                id="appsec",
                manager="appsec-manager@example.com",
                members=["dev@example.com"],
                slack="#appsec-triage",
                ticket_system="github",
                jira_project=None,
            ),
        ]
    )


def _candidate(
    owner_type: OwnerType = OwnerType.USER,
    owner_ref: str = "dev@example.com",
    source: OwnershipSource = OwnershipSource.CODEOWNERS,
    confidence: float = 0.9,
) -> OwnershipCandidate:
    return OwnershipCandidate(
        source=source, owner_type=owner_type, owner_ref=owner_ref, confidence=confidence
    )


def test_owner_of_asset_resolves_to_user_and_manager_of_owner_resolves_team_manager() -> None:
    """Mirrors this is
    Stage 7's DoD case — "a Jira ticket assigned to the right engineer with
    their manager on the watchers list".
    """
    category = _category("owner_of_asset", ["manager_of_owner"])
    ownership = MergeResult(outcome=MergeOutcome.RESOLVED, top=_candidate())

    resolved = resolve_route(category, "high", teams=_teams(), ownership=ownership, now=_NOW)

    assert resolved.assignee.address == "dev@example.com"
    assert resolved.cc[0].address == "appsec-manager@example.com"


def test_low_confidence_attribution_carries_a_note() -> None:
    category = _category("owner_of_asset", [])
    ownership = MergeResult(
        outcome=MergeOutcome.RESOLVED,
        top=_candidate(source=OwnershipSource.TEAM_PATTERN, confidence=0.6),
    )

    resolved = resolve_route(category, "high", teams=_teams(), ownership=ownership, now=_NOW)

    assert resolved.assignee.note is not None
    assert "inferred" in resolved.assignee.note


def test_manual_or_codeowners_attribution_has_no_note() -> None:
    category = _category("owner_of_asset", [])
    ownership = MergeResult(
        outcome=MergeOutcome.RESOLVED,
        top=_candidate(source=OwnershipSource.MANUAL, confidence=0.7),
    )

    resolved = resolve_route(category, "high", teams=_teams(), ownership=ownership, now=_NOW)
    assert resolved.assignee.note is None


def test_orphan_asset_leaves_assignee_unresolved_with_note() -> None:
    category = _category("owner_of_asset", ["manager_of_owner"])

    resolved = resolve_route(category, "high", teams=_teams(), ownership=None, now=_NOW)

    assert resolved.assignee.address is None
    assert resolved.assignee.note is not None
    assert resolved.cc[0].address is None


def test_literal_team_resolves_to_its_manager_and_ticket_system() -> None:
    category = _category("appsec", ["appsec"])

    resolved = resolve_route(category, "high", teams=_teams(), ownership=None, now=_NOW)

    assert resolved.assignee.address == "appsec-manager@example.com"
    assert resolved.cc[0].address == "appsec-manager@example.com"
    assert resolved.ticket_system is not None
    assert resolved.ticket_system.value == "github"


def test_literal_email_used_as_is() -> None:
    category = _category("oncall@example.com", [])

    resolved = resolve_route(category, "high", teams=_teams(), ownership=None, now=_NOW)
    assert resolved.assignee.address == "oncall@example.com"


def test_unresolvable_spec_produces_a_note() -> None:
    category = _category("not-a-team-or-email", [])

    resolved = resolve_route(category, "high", teams=_teams(), ownership=None, now=_NOW)
    assert resolved.assignee.address is None
    assert "unresolvable" in (resolved.assignee.note or "")


def test_sla_days_falls_back_when_severity_key_missing() -> None:
    category = _category("appsec", [], sla_days={"critical": 3})

    resolved = resolve_route(category, "low", teams=_teams(), ownership=None, now=_NOW)
    assert resolved.sla_days == 3


def test_autonomy_level_carried_through() -> None:
    category = _category("appsec", [], autonomy_level=2)

    resolved = resolve_route(category, "high", teams=_teams(), ownership=None, now=_NOW)
    assert resolved.autonomy_level == 2


def test_team_channel_notify_resolves_via_ownership() -> None:
    category = _category("owner_of_asset", [], notify_channels=["team_channel"])
    ownership = MergeResult(
        outcome=MergeOutcome.RESOLVED,
        top=_candidate(owner_type=OwnerType.TEAM, owner_ref="appsec"),
    )

    resolved = resolve_route(category, "high", teams=_teams(), ownership=ownership, now=_NOW)
    assert resolved.notify_channels == ["#appsec-triage"]
