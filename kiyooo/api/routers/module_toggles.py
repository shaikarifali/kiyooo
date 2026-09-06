"""GET/PATCH /api/module-toggles — lets a user turn an optional attack-surface
module (cloud, containers, repos, mobile, attack-paths) on or off in the web
UI. Purely a UI convenience: flipping a module off never touches the API,
CLI, ingest pipeline, or already-ingested data for that domain — it only
hides the nav entry and gates the page (`ModuleGate` on the web side).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import ModuleToggleOut, ModuleToggleUpdateRequest
from kiyooo.db.repo.module_toggle import MODULE_KEYS, ModuleToggleRepository

router = APIRouter()


@router.get("", response_model=list[ModuleToggleOut])
async def list_module_toggles(session: SessionDep) -> list[ModuleToggleOut]:
    toggles = await ModuleToggleRepository(session).list_all()
    return [ModuleToggleOut.model_validate(t) for t in toggles]


@router.patch("/{module_key}", response_model=ModuleToggleOut)
async def set_module_toggle(
    module_key: str, body: ModuleToggleUpdateRequest, session: SessionDep
) -> ModuleToggleOut:
    if module_key not in MODULE_KEYS:
        raise HTTPException(status_code=404, detail=f"unknown module {module_key!r}")
    toggle = await ModuleToggleRepository(session).set_enabled(
        module_key, enabled=body.enabled, updated_at=datetime.now(UTC)
    )
    return ModuleToggleOut.model_validate(toggle)
