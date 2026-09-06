"""App-construction and route-registration smoke test. Route handlers
construct real repos from a real `AsyncSession` (same as every CLI `_run_*`
function) — most of them need `Asset`/`Evidence`/`Verdict`, which carry
Postgres-only JSONB/ARRAY/pgvector columns SQLite can't back, so full
request/response integration tests aren't possible without a live
Postgres, the same "real code, untested by the suite" treatment every
other DB-touching function in this project gets (see
`kiyooo/graph/queries.py`, never covered either). What *is* testable
without a database is that the app assembles: every declared route
exists, the lifespan doesn't blow up on a config-only startup, and
`/healthz` responds.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from kiyooo.api.app import create_app
from kiyooo.config import Settings

_EXPECTED_PATHS = {
    "/healthz",
    "/api/assets",
    "/api/assets/{asset_id}",
    "/api/assets/{asset_id}/ownership",
    "/api/findings",
    "/api/findings/{finding_id}",
    "/api/findings/{finding_id}/review",
    "/api/changes",
    "/api/scan-runs",
    "/api/coverage",
    "/api/categories",
    "/api/categories/{category_id}/preview",
    "/api/dashboard",
    "/api/teams",
    "/api/organizations",
    "/api/seeds",
    "/api/seeds/{seed_id}/disable",
    "/api/exclusions",
    "/api/model-pins",
    "/api/model-pins/defaults",
    "/api/model-pins/test",
    "/api/ingest/sources",
    "/api/ingest/sources/{source_id}",
    "/api/ingest/sources/{source_id}/sync",
    "/api/ingest/unmapped",
    "/api/ingest/test",
    "/api/cloud/accounts",
    "/api/cloud/accounts/{account_id}",
    "/api/cloud/accounts/{account_id}/sync",
    "/api/containers/scans",
    "/api/containers/scans/{scan_id}",
    "/api/containers/scans/{scan_id}/sync",
    "/api/repos/scans",
    "/api/repos/scans/{scan_id}",
    "/api/repos/scans/{scan_id}/sync",
    "/api/mobile/scans",
    "/api/mobile/scans/{scan_id}",
    "/api/mobile/scans/{scan_id}/sync",
    "/api/attack-paths",
    "/api/module-toggles",
    "/api/module-toggles/{module_key}",
}


def test_app_boots_and_healthz_responds() -> None:
    app = create_app(Settings())
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


def test_every_stage_10_resource_has_a_route() -> None:
    app = create_app(Settings())
    with TestClient(app) as client:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        paths = set(resp.json()["paths"])
        assert paths >= _EXPECTED_PATHS


def test_cors_configured_for_the_next_js_dev_origin() -> None:
    app = create_app(Settings())
    with TestClient(app) as client:
        resp = client.get("/healthz", headers={"Origin": "http://localhost:3000"})
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
