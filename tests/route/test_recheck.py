from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.config import CategoryDefinition, PredicateBlock, RouteConfig
from kiyooo.db.models import (
    Asset,
    AssetType,
    Evidence,
    EvidenceKind,
    Finding,
    FindingDetector,
    FindingStatus,
    Severity,
)
from kiyooo.route.recheck import RecheckResult, recheck_finding

_NOW = datetime.now(UTC)
_SLA = {"critical": 1, "high": 7, "medium": 30}


def _category(**overrides: object) -> CategoryDefinition:
    defaults: dict[str, object] = dict(
        id="exposed-database",
        name="Database exposed",
        version=1,
        severity_base="critical",
        applies_to=["tcp_service"],
        detect=PredicateBlock(any_of=[{"port_in": [3306]}]),
        triage_hints="test",
        route=RouteConfig(assign_to="appsec", sla_days=_SLA),
    )
    defaults.update(overrides)
    return CategoryDefinition.model_validate(defaults)


def _asset() -> Asset:
    return Asset(
        id=uuid.uuid4(),
        type=AssetType.TCP_SERVICE,
        value="10.0.0.5:3306",
        first_seen=_NOW,
        last_seen=_NOW,
        confidence_in_scope=1.0,
        attributes={"port": 3306},
    )


def _port_banner_evidence(asset: Asset, port: int) -> Evidence:
    return Evidence(
        id=f"ev_test_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=asset.id,
        kind=EvidenceKind.PORT_BANNER,
        source_tool="test",
        collected_at=_NOW,
        content_inline={"port": port},
        content_hash="hash",
    )


def _finding(asset: Asset, category: CategoryDefinition) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=asset.id,
        category_id=category.id,
        raw_severity=Severity.CRITICAL,
        title=category.name,
        detector=FindingDetector.RULE,
        fingerprint="fp",
        first_seen=_NOW,
        last_seen=_NOW,
        status=FindingStatus.VERIFICATION_PENDING,
    )


def test_still_matches_is_regressed() -> None:
    category = _category()
    asset = _asset()
    finding = _finding(asset, category)
    evidence = [_port_banner_evidence(asset, 3306)]
    result = recheck_finding(finding, category, asset, evidence, now=_NOW)
    assert result == RecheckResult.REGRESSED


def test_no_longer_matches_is_fixed() -> None:
    category = _category()
    asset = _asset()
    finding = _finding(asset, category)
    # port 3306 no longer shows up in fresh evidence — no more open port.
    result = recheck_finding(finding, category, asset, [], now=_NOW)
    assert result == RecheckResult.FIXED


def test_suppressed_by_suppress_if_counts_as_fixed() -> None:
    category = _category(suppress_if=[{"port_in": [3306]}])
    asset = _asset()
    finding = _finding(asset, category)
    evidence = [_port_banner_evidence(asset, 3306)]
    result = recheck_finding(finding, category, asset, evidence, now=_NOW)
    assert result == RecheckResult.FIXED


def test_missing_category_is_no_longer_applicable() -> None:
    asset = _asset()
    finding = _finding(asset, _category())
    result = recheck_finding(finding, None, asset, [], now=_NOW)
    assert result == RecheckResult.NO_LONGER_APPLICABLE


def test_disabled_category_is_no_longer_applicable() -> None:
    category = _category(enabled=False)
    asset = _asset()
    finding = _finding(asset, category)
    result = recheck_finding(finding, category, asset, [], now=_NOW)
    assert result == RecheckResult.NO_LONGER_APPLICABLE
