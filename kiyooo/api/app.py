"""FastAPI app: assets, findings (+verdict+evidence),
change feed, scan runs, review actions, ownership override, coverage
stats. OpenAPI spec is FastAPI's automatic `/openapi.json` — no separate
spec to hand-maintain.

No auth — see `deps.py`'s docstring; RBAC/SSO is Stage 11's explicitly-
deferred item. Run behind a trusted network / reverse proxy until that
lands, same caveat every other unauthenticated dev-mode tool in this
project carries.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kiyooo.api.routers import (
    assets,
    attack_paths,
    categories,
    changes,
    cloud,
    containers,
    coverage,
    dashboard,
    exclusions,
    findings,
    ingest,
    mobile,
    model_pins,
    module_toggles,
    organizations,
    ownership,
    repos,
    review,
    scan_runs,
    seeds,
    teams,
)
from kiyooo.config import Settings, load_org_context
from kiyooo.db.session import make_engine, make_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(resolved_settings)
        app.state.session_factory = make_session_factory(engine)
        app.state.settings = resolved_settings
        app.state.org_context = load_org_context(resolved_settings.org_context_path)
        yield
        await engine.dispose()

    app = FastAPI(
        title="kiyooo",
        description="AI-triaged Attack Surface Management",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.api_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
    app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
    app.include_router(changes.router, prefix="/api/changes", tags=["changes"])
    app.include_router(scan_runs.router, prefix="/api/scan-runs", tags=["scan-runs"])
    app.include_router(coverage.router, prefix="/api/coverage", tags=["coverage"])
    app.include_router(review.router, prefix="/api", tags=["review"])
    app.include_router(ownership.router, prefix="/api", tags=["ownership"])
    app.include_router(categories.router, prefix="/api/categories", tags=["categories"])
    app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
    app.include_router(teams.router, prefix="/api/teams", tags=["teams"])
    app.include_router(organizations.router, prefix="/api/organizations", tags=["organizations"])
    app.include_router(seeds.router, prefix="/api/seeds", tags=["seeds"])
    app.include_router(exclusions.router, prefix="/api/exclusions", tags=["exclusions"])
    app.include_router(model_pins.router, prefix="/api/model-pins", tags=["model-pins"])
    app.include_router(ingest.router, prefix="/api/ingest", tags=["ingest"])
    app.include_router(cloud.router, prefix="/api/cloud", tags=["cloud"])
    app.include_router(containers.router, prefix="/api/containers", tags=["containers"])
    app.include_router(repos.router, prefix="/api/repos", tags=["repos"])
    app.include_router(mobile.router, prefix="/api/mobile", tags=["mobile"])
    app.include_router(attack_paths.router, prefix="/api/attack-paths", tags=["attack-paths"])
    app.include_router(module_toggles.router, prefix="/api/module-toggles", tags=["module-toggles"])

    @app.get("/healthz", tags=["meta"])
    async def healthz() -> dict[str, bool]:
        return {"ok": True}

    return app


app = create_app()
