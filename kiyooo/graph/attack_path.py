"""Attack path engine — the last of the domain-
expansion stages, and the one that needs no new external tool: pure graph
traversal over the asset graph Stage 2 already builds, which gets richer
as Stages 13-16 add new asset types and their categories get linked in via
`is_sensitive_target`.

Report one correlated path instead of N unrelated findings. A path
connects an asset with an ordinary weakness to a *sensitive* asset (one
whose active finding's category has `is_sensitive_target: true` in
org-context — a database, an object store, a leaked credential; see
`config.py::CategoryDefinition`) via the shortest chain of `AssetEdge`
hops between them. Finding two unrelated problems that happen to share an
asset graph is exactly the "seven unrelated findings" this collapses into
one story.

Deliberately simpler than the design's original sketch in one respect: this
computes paths on demand from the current graph/finding state rather than
maintaining a persisted `attack_path` table — there is no staleness to
manage, and the traversal itself is cheap for the graph sizes this project
targets. Revisit with a persisted table only if a real deployment's graph
size makes on-demand traversal too slow, not preemptively.

Pure functions over already-loaded rows, not a session — same reasoning
`detect/predicates.py` gives for taking plain data: directly unit-testable
against a hand-built graph, no DB/fixtures needed.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from uuid import UUID

from kiyooo.db.models import Asset, AssetEdge, Finding, FindingStatus, Severity

_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}
_INACTIVE_STATUSES = frozenset({FindingStatus.FIXED, FindingStatus.SUPPRESSED})
DEFAULT_MAX_HOPS = 6


@dataclass(frozen=True, slots=True)
class AttackPathHop:
    asset_id: UUID
    asset_type: str
    asset_value: str
    finding_id: UUID | None
    finding_category_id: str | None
    finding_severity: str | None


@dataclass(frozen=True, slots=True)
class AttackPath:
    hops: list[AttackPathHop]
    score: float
    sensitive_category_id: str


def _active_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.status not in _INACTIVE_STATUSES]


def _build_adjacency(
    edges: list[AssetEdge],
) -> tuple[dict[UUID, set[UUID]], dict[tuple[UUID, UUID], float]]:
    """Undirected for traversal purposes — a `hosted_on`/`owned_by`/
    `resolves_to` edge describes a real infrastructure relationship an
    attacker can move along regardless of which end our recon happened to
    discover first; direction matters for what the edge *means*, not for
    whether reachability can flow across it.
    """
    adjacency: dict[UUID, set[UUID]] = {}
    confidence: dict[tuple[UUID, UUID], float] = {}
    for edge in edges:
        adjacency.setdefault(edge.src_asset_id, set()).add(edge.dst_asset_id)
        adjacency.setdefault(edge.dst_asset_id, set()).add(edge.src_asset_id)
        confidence[(edge.src_asset_id, edge.dst_asset_id)] = edge.confidence
        confidence[(edge.dst_asset_id, edge.src_asset_id)] = edge.confidence
    return adjacency, confidence


def _nearest_other_finding_path(
    start: UUID,
    adjacency: dict[UUID, set[UUID]],
    findings_by_asset: dict[UUID, list[Finding]],
    max_hops: int,
) -> list[UUID] | None:
    """BFS guarantees the first qualifying node popped is at minimum
    distance — the shortest, most directly actionable chain, not just *a*
    chain.
    """
    visited = {start}
    queue: deque[tuple[UUID, list[UUID]]] = deque([(start, [start])])
    while queue:
        node, path = queue.popleft()
        if node != start and node in findings_by_asset:
            return path
        if len(path) - 1 >= max_hops:
            continue
        for neighbor in adjacency.get(node, ()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, [*path, neighbor]))
    return None


def _worst_finding(findings: list[Finding]) -> Finding:
    return max(findings, key=lambda f: _SEVERITY_WEIGHT.get(f.raw_severity, 0.0))


def _build_hops(
    path: list[UUID],
    assets_by_id: dict[UUID, Asset],
    findings_by_asset: dict[UUID, list[Finding]],
) -> list[AttackPathHop]:
    hops = []
    for asset_id in path:
        asset = assets_by_id[asset_id]
        finding = None
        asset_findings = findings_by_asset.get(asset_id)
        if asset_findings:
            finding = _worst_finding(asset_findings)
        hops.append(
            AttackPathHop(
                asset_id=asset.id,
                asset_type=asset.type.value,
                asset_value=asset.value,
                finding_id=finding.id if finding else None,
                finding_category_id=finding.category_id if finding else None,
                finding_severity=finding.raw_severity.value if finding else None,
            )
        )
    return hops


def _score_path(
    path: list[UUID],
    edge_confidence: dict[tuple[UUID, UUID], float],
    findings_by_asset: dict[UUID, list[Finding]],
) -> float:
    if len(path) < 2:
        mean_confidence = 1.0
    else:
        confidences = [
            edge_confidence.get((path[i], path[i + 1]), 0.5) for i in range(len(path) - 1)
        ]
        mean_confidence = sum(confidences) / len(confidences)

    worst_weight = 0.0
    for asset_id in path:
        for finding in findings_by_asset.get(asset_id, []):
            worst_weight = max(worst_weight, _SEVERITY_WEIGHT.get(finding.raw_severity, 0.0))
    if worst_weight == 0.0:
        worst_weight = 0.1

    return round(mean_confidence * worst_weight, 4)


def find_attack_paths(
    assets: list[Asset],
    edges: list[AssetEdge],
    findings: list[Finding],
    *,
    sensitive_category_ids: set[str],
    max_hops: int = DEFAULT_MAX_HOPS,
) -> list[AttackPath]:
    """For every asset with an active finding in a sensitive category,
    find the shortest graph path to the nearest *other* asset that also
    has an active finding — reported entry-to-sensitive-asset (the
    attacker's direction), highest score first.

    One path per sensitive finding, not per sensitive asset: an asset with
    two distinct sensitive findings (rare, but Stage 14/15's bucket
    categories make it possible) gets two entries, since they may connect
    to different weaknesses or none at all.
    """
    active = _active_findings(findings)
    findings_by_asset: dict[UUID, list[Finding]] = {}
    for finding in active:
        findings_by_asset.setdefault(finding.asset_id, []).append(finding)

    assets_by_id = {asset.id: asset for asset in assets}
    adjacency, edge_confidence = _build_adjacency(edges)

    paths: list[AttackPath] = []
    for finding in active:
        if finding.category_id not in sensitive_category_ids:
            continue
        path = _nearest_other_finding_path(finding.asset_id, adjacency, findings_by_asset, max_hops)
        if path is None:
            continue
        entry_to_sensitive = list(reversed(path))
        paths.append(
            AttackPath(
                hops=_build_hops(entry_to_sensitive, assets_by_id, findings_by_asset),
                score=_score_path(path, edge_confidence, findings_by_asset),
                sensitive_category_id=finding.category_id,
            )
        )

    paths.sort(key=lambda p: p.score, reverse=True)
    return paths
