"""Minimal `assets query` filter language and the decommission-candidate
query.

`kiyooo assets query <expr>...` takes one or more `field=value` /
`field!=value` clauses, ANDed together. This is deliberately minimal — no
substring/regex/OR support. The design doesn't specify a fuller query language
anywhere else in the plan, and building one ahead of an actual need would be
exactly the kind of unrequested abstraction CLAUDE.md rules out. Extend this
once a real use case needs more than exact-match AND.

Decommission-candidates implements three of the design's four named conditions
(reachable, no owner >=0.8 confidence, unchanged in N scans) — the fourth,
"serves no traffic signal," has no data source anywhere in the schema, and
approximating "no data" as "no traffic" would bias the list toward flagging
things that might genuinely be busy. The list is a human-reviewed lead list,
never an autonomous action, so under-flagging (three conditions, not four) is
the safer failure mode than a false decommission recommendation.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kiyooo.db.models import Asset, AssetType, ChangeEvent, Ownership
from kiyooo.db.repo.scan_run import ScanRunRepository

DEFAULT_UNCHANGED_SCAN_THRESHOLD = 3
_SUPPORTED_FIELDS = {"type", "is_active", "value"}


class QueryError(ValueError):
    pass


def _parse_clause(raw: str) -> tuple[str, bool, str]:
    if "!=" in raw:
        field, _, value = raw.partition("!=")
        negated = True
    elif "=" in raw:
        field, _, value = raw.partition("=")
        negated = False
    else:
        raise QueryError(f"malformed clause {raw!r}: expected field=value or field!=value")

    field = field.strip()
    value = value.strip()
    if field not in _SUPPORTED_FIELDS:
        raise QueryError(f"unsupported field {field!r}; supported: {sorted(_SUPPORTED_FIELDS)}")
    if not value:
        raise QueryError(f"malformed clause {raw!r}: empty value")
    return field, negated, value


async def query_assets(session: AsyncSession, clauses: list[str]) -> list[Asset]:
    stmt = select(Asset)
    for raw in clauses:
        field, negated, value = _parse_clause(raw)

        if field == "type":
            try:
                type_value = AssetType(value.lower())
            except ValueError:
                known = [t.value for t in AssetType]
                raise QueryError(f"unknown asset type {value!r}; one of {known}") from None
            condition = Asset.type != type_value if negated else Asset.type == type_value

        elif field == "is_active":
            lowered = value.lower()
            if lowered not in ("true", "false"):
                raise QueryError(f"is_active must be true or false, got {value!r}")
            bool_value = lowered == "true"
            condition = Asset.is_active != bool_value if negated else Asset.is_active == bool_value

        else:  # "value"
            condition = Asset.value != value if negated else Asset.value == value

        stmt = stmt.where(condition)

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def decommission_candidates(
    session: AsyncSession,
    scan_run_repo: ScanRunRepository,
    *,
    unchanged_scan_threshold: int = DEFAULT_UNCHANGED_SCAN_THRESHOLD,
) -> list[Asset]:
    recent_runs = await scan_run_repo.recent_completed(unchanged_scan_threshold)
    if len(recent_runs) < unchanged_scan_threshold:
        return []  # not enough scan history yet to call anything "unchanged"

    recent_run_ids = [run.id for run in recent_runs]
    owned_subquery = select(Ownership.asset_id).where(Ownership.confidence >= 0.8).distinct()
    changed_subquery = (
        select(ChangeEvent.asset_id).where(ChangeEvent.scan_run_id.in_(recent_run_ids)).distinct()
    )

    stmt = (
        select(Asset)
        .where(Asset.is_active.is_(True))
        .where(Asset.id.notin_(owned_subquery))
        .where(Asset.id.notin_(changed_subquery))
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())
