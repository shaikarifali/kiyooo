"""Routing orchestrator: for every TRIAGED finding whose
latest verdict is a true positive, resolves the route, renders + lints the
ticket, and — per the category's autonomy level — either does nothing
(shadow), drafts an `Approval` for a human to send, or files/reopens a
`Ticket` directly via the resolved sink. Batches by `cluster_id`: one ticket
per cluster, not one per finding, with every clustered asset listed in the
body — the "cluster-level tickets... asset list as a table" deliverable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import ApprovalDraftKind, FindingStatus, Severity, TicketSystem, VerdictValue
from kiyooo.enrich.ownership import merge_existing
from kiyooo.route.autonomy import RouteAction, decide_action
from kiyooo.route.policy import resolve_route
from kiyooo.route.ticket_contract import (
    TicketContractViolation,
    build_ticket_subject,
    render_ticket,
)

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    import httpx

    from kiyooo.config import OrgContext
    from kiyooo.db.models import Finding, Verdict
    from kiyooo.db.repo.approval import ApprovalRepository
    from kiyooo.db.repo.asset import AssetRepository
    from kiyooo.db.repo.finding import FindingRepository
    from kiyooo.db.repo.ownership import OwnershipRepository
    from kiyooo.db.repo.ticket import TicketRepository
    from kiyooo.db.repo.verdict import VerdictRepository
    from kiyooo.route.sinks.base import TicketSink


@dataclass(slots=True)
class RouteOutcome:
    shadowed: int = 0
    drafted: int = 0
    filed: int = 0
    reopened: int = 0
    skipped_no_verdict: int = 0
    contract_violations: list[str] = field(default_factory=list)


async def _latest_true_positive(
    finding: Finding, verdict_repo: VerdictRepository
) -> Verdict | None:
    verdicts = await verdict_repo.list_for_finding(finding.id)
    if not verdicts:
        return None
    latest = verdicts[-1]
    return latest if latest.verdict == VerdictValue.TRUE_POSITIVE else None


def _group_by_cluster(findings: list[Finding]) -> list[list[Finding]]:
    clusters: dict[UUID, list[Finding]] = {}
    singles: list[list[Finding]] = []
    for finding in findings:
        if finding.cluster_id is not None:
            clusters.setdefault(finding.cluster_id, []).append(finding)
        else:
            singles.append([finding])
    return list(clusters.values()) + singles


async def route_findings(
    org_context: OrgContext,
    findings: list[Finding],
    *,
    sinks: dict[TicketSystem, TicketSink],
    http_client: httpx.AsyncClient,
    org_context_path: Path,
    asset_repo: AssetRepository,
    ownership_repo: OwnershipRepository,
    verdict_repo: VerdictRepository,
    finding_repo: FindingRepository,
    ticket_repo: TicketRepository,
    approval_repo: ApprovalRepository,
    now: datetime | None = None,
) -> RouteOutcome:
    now = now or datetime.now(UTC)
    outcome = RouteOutcome()

    for group in _group_by_cluster(findings):
        primary = min(group, key=lambda f: f.first_seen)
        verdict = await _latest_true_positive(primary, verdict_repo)
        if verdict is None:
            outcome.skipped_no_verdict += 1
            continue

        category = org_context.categories.get(primary.category_id)
        if category is None:
            outcome.skipped_no_verdict += 1
            continue

        asset = await asset_repo.get(primary.asset_id)
        if asset is None:
            continue

        ownership = await merge_existing(asset.id, ownership_repo)
        severity = verdict.adjusted_severity.value
        resolved = resolve_route(
            category, severity, teams=org_context.teams, ownership=ownership, now=now
        )

        cluster_asset_values: list[str] = []
        for member in group:
            member_asset = await asset_repo.get(member.asset_id)
            if member_asset is not None:
                cluster_asset_values.append(member_asset.value)

        context: dict[str, object] = {
            "category_name": category.name,
            "severity": severity,
            "asset_value": asset.value,
            "asset_type": asset.type.value,
            "finding_title": primary.title,
            "finding_description": primary.description,
            "cluster_assets": cluster_asset_values,
            "reasoning": verdict.reasoning,
            "citations": verdict.citations,
            "business_impact_hypothesis": verdict.business_impact_hypothesis,
            "exploitability": verdict.exploitability or {},
            "remediation": verdict.remediation or {},
            "compensating_controls": verdict.compensating_controls,
            "ownership_confidence": resolved.ownership_confidence,
            "ownership_source": resolved.ownership_source,
            "ownership_note": resolved.ownership_note,
            "sla_due_at": resolved.sla_due_at,
        }
        subject = build_ticket_subject(
            severity=severity, category_name=category.name, asset_value=asset.value
        )
        template_path = (
            org_context_path / category.route.ticket_template
            if category.route.ticket_template
            else None
        )

        try:
            rendered = render_ticket(context, subject=subject, template_path=template_path)
        except TicketContractViolation as exc:
            outcome.contract_violations.append(f"{category.id}: missing {exc.missing}")
            continue

        action = decide_action(resolved.autonomy_level, Severity(severity))
        cc_addresses = [target.address for target in resolved.cc if target.address]

        if action == RouteAction.SHADOW:
            outcome.shadowed += len(group)
            continue

        if action == RouteAction.DRAFT_FOR_APPROVAL:
            await approval_repo.create(
                finding_id=primary.id,
                draft_kind=ApprovalDraftKind.TICKET,
                rendered_body=rendered.body,
                rendered_subject=rendered.subject,
                target_assignee=resolved.assignee.address,
                target_cc=cc_addresses,
            )
            outcome.drafted += len(group)
            continue

        system = resolved.ticket_system or TicketSystem.WEBHOOK
        sink = sinks.get(system)
        if sink is None:
            outcome.contract_violations.append(
                f"{category.id}: no sink configured for {system.value}"
            )
            continue

        existing = await ticket_repo.get_by_finding(primary.id)
        if existing is not None:
            result = await sink.reopen(
                http_client, external_key=existing.external_key or "", body=rendered.body
            )
            await ticket_repo.set_status(existing.id, result.status)
            outcome.reopened += len(group)
        else:
            result = await sink.create(
                http_client,
                subject=rendered.subject,
                body=rendered.body,
                assignee=resolved.assignee.address,
                cc=cc_addresses,
                sla_due_at=resolved.sla_due_at,
            )
            await ticket_repo.create(
                finding_id=primary.id,
                system=system,
                external_key=result.external_key,
                assignee=resolved.assignee.address,
                cc=cc_addresses,
                sla_due_at=resolved.sla_due_at,
                status=result.status,
                created_at=now,
            )
            outcome.filed += len(group)

        for member in group:
            await finding_repo.mark_status(member.id, FindingStatus.ROUTED)

    return outcome
