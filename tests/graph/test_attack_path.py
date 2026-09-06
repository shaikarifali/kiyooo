from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import (
    AssetEdge,
    AssetEdgeRelation,
    AssetType,
    Finding,
    FindingDetector,
    FindingStatus,
    Severity,
)
from kiyooo.graph.attack_path import find_attack_paths
from tests.recon.factories import make_asset

_NOW = datetime.now(UTC)


def _edge(src: uuid.UUID, dst: uuid.UUID, *, confidence: float = 0.9) -> AssetEdge:
    return AssetEdge(
        id=uuid.uuid4(),
        src_asset_id=src,
        dst_asset_id=dst,
        relation=AssetEdgeRelation.HOSTED_ON,
        confidence=confidence,
        discovered_by="test",
        first_seen=_NOW,
        last_seen=_NOW,
    )


def _finding(
    asset_id: uuid.UUID,
    category_id: str,
    *,
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.NEW,
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=asset_id,
        category_id=category_id,
        raw_severity=severity,
        title=category_id,
        description=None,
        detector=FindingDetector.RULE,
        detector_ref=None,
        fingerprint=uuid.uuid4().hex,
        cluster_id=uuid.uuid4(),
        status=status,
        first_seen=_NOW,
        last_seen=_NOW,
        resolved_at=None,
    )


def test_finds_shortest_path_between_weakness_and_sensitive_asset() -> None:
    lb = make_asset(AssetType.HTTP_SERVICE, "lb.example.com")
    pod = make_asset(AssetType.K8S_WORKLOAD, "default/Deployment/web-app")
    bucket = make_asset(AssetType.CLOUD_RESOURCE, "arn:aws:s3:::acme-data")

    edges = [_edge(lb.id, pod.id), _edge(pod.id, bucket.id)]
    findings = [
        _finding(pod.id, "vulnerable-base-image", severity=Severity.HIGH),
        _finding(bucket.id, "public-object-storage", severity=Severity.CRITICAL),
    ]

    paths = find_attack_paths(
        [lb, pod, bucket],
        edges,
        findings,
        sensitive_category_ids={"public-object-storage"},
    )

    assert len(paths) == 1
    path = paths[0]
    assert path.sensitive_category_id == "public-object-storage"
    assert [h.asset_id for h in path.hops] == [pod.id, bucket.id]
    assert path.hops[0].finding_category_id == "vulnerable-base-image"
    assert path.hops[1].finding_category_id == "public-object-storage"
    assert path.score > 0


def test_prefers_shortest_path_when_multiple_exist() -> None:
    entry = make_asset(AssetType.DOMAIN, "app.example.com")
    detour = make_asset(AssetType.SUBDOMAIN, "detour.example.com")
    near = make_asset(AssetType.TCP_SERVICE, "10.0.0.1:5432")
    sensitive = make_asset(AssetType.CLOUD_RESOURCE, "arn:aws:rds:acme-prod")

    # Two routes from `near` to `sensitive`: direct, and via a longer detour
    # through `entry`/`detour` — the direct one must win.
    edges = [
        _edge(near.id, sensitive.id),
        _edge(near.id, entry.id),
        _edge(entry.id, detour.id),
        _edge(detour.id, sensitive.id),
    ]
    findings = [
        _finding(near.id, "exposed-database", severity=Severity.HIGH),
        _finding(sensitive.id, "public-database-instance", severity=Severity.CRITICAL),
    ]

    paths = find_attack_paths(
        [entry, detour, near, sensitive],
        edges,
        findings,
        sensitive_category_ids={"public-database-instance"},
    )

    assert len(paths) == 1
    assert [h.asset_id for h in paths[0].hops] == [near.id, sensitive.id]


def test_no_path_when_sensitive_asset_is_isolated() -> None:
    weak = make_asset(AssetType.TCP_SERVICE, "10.0.0.1:5432")
    sensitive = make_asset(AssetType.CLOUD_RESOURCE, "arn:aws:s3:::isolated")
    findings = [
        _finding(weak.id, "exposed-database"),
        _finding(sensitive.id, "public-object-storage", severity=Severity.CRITICAL),
    ]

    paths = find_attack_paths(
        [weak, sensitive],
        [],  # no edges at all
        findings,
        sensitive_category_ids={"public-object-storage"},
    )
    assert paths == []


def test_no_sensitive_categories_configured_yields_no_paths() -> None:
    a = make_asset(AssetType.TCP_SERVICE, "10.0.0.1:5432")
    b = make_asset(AssetType.CLOUD_RESOURCE, "arn:aws:s3:::acme-data")
    findings = [_finding(a.id, "exposed-database"), _finding(b.id, "public-object-storage")]

    paths = find_attack_paths([a, b], [_edge(a.id, b.id)], findings, sensitive_category_ids=set())
    assert paths == []


def test_fixed_and_suppressed_findings_are_ignored() -> None:
    weak = make_asset(AssetType.TCP_SERVICE, "10.0.0.1:5432")
    sensitive = make_asset(AssetType.CLOUD_RESOURCE, "arn:aws:s3:::acme-data")
    findings = [
        _finding(weak.id, "exposed-database", status=FindingStatus.FIXED),
        _finding(sensitive.id, "public-object-storage", status=FindingStatus.SUPPRESSED),
    ]

    paths = find_attack_paths(
        [weak, sensitive],
        [_edge(weak.id, sensitive.id)],
        findings,
        sensitive_category_ids={"public-object-storage"},
    )
    assert paths == []


def test_respects_max_hops() -> None:
    a = make_asset(AssetType.TCP_SERVICE, "a")
    b = make_asset(AssetType.TCP_SERVICE, "b")
    c = make_asset(AssetType.TCP_SERVICE, "c")
    sensitive = make_asset(AssetType.CLOUD_RESOURCE, "sensitive")
    edges = [_edge(a.id, b.id), _edge(b.id, c.id), _edge(c.id, sensitive.id)]
    findings = [
        _finding(a.id, "exposed-database"),
        _finding(sensitive.id, "public-object-storage", severity=Severity.CRITICAL),
    ]

    paths = find_attack_paths(
        [a, b, c, sensitive],
        edges,
        findings,
        sensitive_category_ids={"public-object-storage"},
        max_hops=2,
    )
    assert paths == []  # true distance is 3 hops, over the cap
