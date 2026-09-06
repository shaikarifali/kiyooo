"""Per-scan immutable `asset_snapshot` rows.

One snapshot per asset touched in a scan run, capturing just enough of that
asset's observable state for `diff/engine.py` to compare consecutive scans.
`state` is a curated subset of the asset's own evidence from this scan_run —
not the full evidence blob — so `state_hash` stays stable across re-runs that
produce byte-identical evidence in a different key order, or with incidental
fields (timestamps, which resolver answered, ...) that shouldn't count as a
"change." Curating what goes into `state` is what makes the DoD's
zero-spurious-events idempotency requirement possible at all.

Only `TCP_SERVICE`, `HTTP_SERVICE`, and `CERT` assets get a meaningful
`state` right now — the fields `diff/rules.py` actually compares (port,
status code / tech / a login-page heuristic, cert serial). Every other asset
type still gets a snapshot row (so `ASSET_NEW`/`ASSET_GONE` work for them),
just with an empty `state` — no finer-grained field-level diff exists for
them yet.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from kiyooo.db.models import Asset, AssetSnapshot, AssetType, Evidence, EvidenceKind
from kiyooo.db.repo.asset_snapshot import AssetSnapshotRepository
from kiyooo.db.repo.evidence import EvidenceRepository

_LOGIN_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "sign in",
    "log in",
    "authentication required",
)


def _first_content(evidence: list[Evidence], kind: EvidenceKind) -> dict[str, object]:
    for item in evidence:
        if item.kind == kind:
            # Evidence over the inline-storage threshold has content_ref set
            # instead (see recon/orchestrator.py's EvidenceWriter) — state
            # diffing only sees inline content for now; that's every evidence
            # kind this function reads today, since none of them include a
            # full response body.
            return item.content_inline or {}
    return {}


def _build_state(asset: Asset, asset_evidence: list[Evidence]) -> dict[str, object]:
    if asset.type == AssetType.TCP_SERVICE:
        record = _first_content(asset_evidence, EvidenceKind.PORT_BANNER)
        return {"port": record.get("port"), "protocol": record.get("protocol", "tcp")}

    if asset.type == AssetType.HTTP_SERVICE:
        record = _first_content(asset_evidence, EvidenceKind.HTTP_RESPONSE)
        status_code = record.get("status_code")
        title = str(record.get("title") or "")
        raw_tech = record.get("tech") or []
        tech = sorted(str(t) for t in raw_tech) if isinstance(raw_tech, list) else []
        requires_auth = status_code in (401, 403) or any(
            keyword in title.lower() for keyword in _LOGIN_KEYWORDS
        )
        return {"status_code": status_code, "tech": tech, "requires_auth": requires_auth}

    if asset.type == AssetType.CERT:
        record = _first_content(asset_evidence, EvidenceKind.TLS_CERT)
        return {
            "subject_cn": record.get("subject_cn"),
            "issuer_cn": record.get("issuer_cn"),
            "serial_number": record.get("serial_number"),
            "not_after": record.get("not_after"),
        }

    return {}


async def build_snapshots(
    asset_snapshot_repo: AssetSnapshotRepository,
    evidence_repo: EvidenceRepository,
    *,
    scan_run_id: UUID,
    assets: list[Asset],
) -> list[AssetSnapshot]:
    all_evidence = await evidence_repo.for_scan_run(scan_run_id)
    evidence_by_asset: dict[UUID, list[Evidence]] = {}
    for item in all_evidence:
        evidence_by_asset.setdefault(item.asset_id, []).append(item)

    now = datetime.now(UTC)
    snapshots = []
    for asset in assets:
        state = _build_state(asset, evidence_by_asset.get(asset.id, []))
        state_json = json.dumps(state, sort_keys=True, default=str)
        state_hash = hashlib.sha256(state_json.encode()).hexdigest()
        snapshot = AssetSnapshot(
            scan_run_id=scan_run_id,
            asset_id=asset.id,
            state_hash=state_hash,
            state=state,
            observed_at=now,
        )
        snapshots.append(await asset_snapshot_repo.add(snapshot))
    return snapshots
