"""Route resolution: turns a category's `route:` block
into concrete assignee/cc/notify_channels/sla for one finding, against
`teams.yaml` and the asset's resolved ownership (Stage 3's
`enrich/ownership/merge.py`).

`assign_to` / each `cc` entry is one of:
  - `owner_of_asset`   -- the asset's resolved owner (Stage 3's merge winner)
  - `manager_of_owner` -- that owner's manager, looked up in teams.yaml
  - a literal team id (teams.yaml `id`)          -- resolves to that team's manager
  - a literal email address (contains "@")        -- used as-is

Pure: no I/O, no database access. Everything it needs — the category, the
teams file, and the ownership merge result — is already loaded/computed by
the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from kiyooo.db.models import OwnershipSource, OwnerType, TicketSystem

if TYPE_CHECKING:
    from kiyooo.config import CategoryDefinition, TeamDefinition, TeamsFile
    from kiyooo.enrich.ownership.merge import MergeResult, OwnershipCandidate

_DEFAULT_SLA_DAYS = 30
_HIGH_CONFIDENCE_SOURCES = frozenset({OwnershipSource.MANUAL, OwnershipSource.CODEOWNERS})


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    address: str | None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedRoute:
    assignee: ResolvedTarget
    cc: list[ResolvedTarget] = field(default_factory=list)
    notify_channels: list[str] = field(default_factory=list)
    sla_days: int = _DEFAULT_SLA_DAYS
    sla_due_at: datetime | None = None
    ticket_system: TicketSystem | None = None
    jira_project: str | None = None
    ownership_confidence: float | None = None
    ownership_source: str | None = None
    ownership_note: str | None = None
    autonomy_level: int = 0


def _team_by_id(teams: list[TeamDefinition], team_id: str) -> TeamDefinition | None:
    return next((t for t in teams if t.id == team_id), None)


def _owning_team_of_user(teams: list[TeamDefinition], email: str) -> TeamDefinition | None:
    return next((t for t in teams if email in t.members), None)


def _attribution_note(candidate: OwnershipCandidate) -> str | None:
    if candidate.source in _HIGH_CONFIDENCE_SOURCES or candidate.confidence >= 0.95:
        return None
    return (
        f"attribution inferred via {candidate.source.value} "
        f"(confidence {candidate.confidence:.2f}) — confirm or reassign"
    )


def _resolve_target(
    spec: str, *, ownership: MergeResult | None, teams: list[TeamDefinition]
) -> ResolvedTarget:
    if spec == "owner_of_asset":
        top = ownership.top if ownership is not None else None
        if top is None:
            return ResolvedTarget(None, "no confirmed owner — asset is an ownership orphan")
        note = _attribution_note(top)
        if top.owner_type == OwnerType.TEAM:
            team = _team_by_id(teams, top.owner_ref)
            return ResolvedTarget(team.manager if team else None, note)
        return ResolvedTarget(top.owner_ref, note)

    if spec == "manager_of_owner":
        top = ownership.top if ownership is not None else None
        if top is None:
            return ResolvedTarget(None, "no confirmed owner to derive a manager from")
        if top.owner_type == OwnerType.TEAM:
            team = _team_by_id(teams, top.owner_ref)
            return ResolvedTarget(team.manager if team else None)
        owning_team = _owning_team_of_user(teams, top.owner_ref)
        if owning_team is None:
            return ResolvedTarget(None, "owner has no team on record — manager unknown")
        return ResolvedTarget(owning_team.manager)

    team = _team_by_id(teams, spec)
    if team is not None:
        return ResolvedTarget(team.manager)

    if "@" in spec:
        return ResolvedTarget(spec)

    return ResolvedTarget(None, f"unresolvable route target: {spec!r}")


def _resolve_channel(
    spec: str, *, ownership: MergeResult | None, teams: list[TeamDefinition]
) -> str | None:
    if spec != "team_channel":
        return spec
    top = ownership.top if ownership is not None else None
    if top is None:
        return None
    team = (
        _team_by_id(teams, top.owner_ref)
        if top.owner_type == OwnerType.TEAM
        else _owning_team_of_user(teams, top.owner_ref)
    )
    return team.slack if team is not None else None


def _sla_days_for(route: CategoryDefinition, severity: str) -> int:
    sla = route.route.sla_days
    if severity in sla:
        return sla[severity]
    for fallback in ("critical", "high", "medium", "low", "info"):
        if fallback in sla:
            return sla[fallback]
    return _DEFAULT_SLA_DAYS


def resolve_route(
    category: CategoryDefinition,
    severity: str,
    *,
    teams: TeamsFile,
    ownership: MergeResult | None,
    now: datetime,
) -> ResolvedRoute:
    route = category.route
    assignee = _resolve_target(route.assign_to, ownership=ownership, teams=teams.teams)
    cc = [_resolve_target(spec, ownership=ownership, teams=teams.teams) for spec in route.cc]
    channels = [
        channel
        for spec in route.notify_channels
        if (channel := _resolve_channel(spec, ownership=ownership, teams=teams.teams)) is not None
    ]

    ticket_system: TicketSystem | None = None
    jira_project: str | None = None
    resolved_team = _team_by_id(teams.teams, route.assign_to)
    if resolved_team is not None:
        ticket_system = (
            TicketSystem(resolved_team.ticket_system) if resolved_team.ticket_system else None
        )
        jira_project = resolved_team.jira_project
    elif ownership is not None and ownership.top is not None:
        owner_team = (
            _team_by_id(teams.teams, ownership.top.owner_ref)
            if ownership.top.owner_type == OwnerType.TEAM
            else _owning_team_of_user(teams.teams, ownership.top.owner_ref)
        )
        if owner_team is not None:
            ticket_system = (
                TicketSystem(owner_team.ticket_system) if owner_team.ticket_system else None
            )
            jira_project = owner_team.jira_project

    sla_days = _sla_days_for(category, severity)
    top = ownership.top if ownership is not None else None

    return ResolvedRoute(
        assignee=assignee,
        cc=cc,
        notify_channels=channels,
        sla_days=sla_days,
        sla_due_at=now + timedelta(days=sla_days),
        ticket_system=ticket_system,
        jira_project=jira_project,
        ownership_confidence=top.confidence if top else None,
        ownership_source=top.source.value if top else None,
        ownership_note=assignee.note,
        autonomy_level=route.autonomy_level,
    )
