"""GET/POST /api/model-pins — the web UI's Model configuration page, and
`GET /api/model-pins/defaults` for what an unpinned role currently falls
back to. Mirrors `kiyooo providers list/pin` exactly (Part D §8 parity).
`POST /api/model-pins/test` is the zero-cost reachability check `kiyooo
providers test` runs — see `llm/connection_test.py`'s docstring for why
it's never a real completion call.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from kiyooo.api.deps import SessionDep, SettingsDep
from kiyooo.api.schemas import (
    ModelPinCreateRequest,
    ModelPinOut,
    ProviderTestRequest,
    ProviderTestResultOut,
    RoleDefaultOut,
)
from kiyooo.db.models import ModelPinRole
from kiyooo.db.repo.model_pin import ModelPinRepository
from kiyooo.llm.connection_test import test_connection
from kiyooo.llm.credentials import resolve_credential

router = APIRouter()


@router.get("", response_model=list[ModelPinOut])
async def list_model_pins(session: SessionDep) -> list[ModelPinOut]:
    pins = await ModelPinRepository(session).list_active()
    return [ModelPinOut.model_validate(p) for p in pins]


@router.get("/defaults", response_model=list[RoleDefaultOut])
async def list_role_defaults(settings: SettingsDep) -> list[RoleDefaultOut]:
    return [
        RoleDefaultOut(
            role=ModelPinRole.BULK, provider=settings.llm_provider, model=settings.bulk_model
        ),
        RoleDefaultOut(
            role=ModelPinRole.ESCALATION,
            provider=settings.escalation_provider,
            model=settings.escalation_model,
        ),
        RoleDefaultOut(
            role=ModelPinRole.EMBEDDING,
            provider=settings.embedding_provider,
            model=settings.embedding_model,
        ),
    ]


@router.post("", response_model=ModelPinOut)
async def create_model_pin(body: ModelPinCreateRequest, session: SessionDep) -> ModelPinOut:
    if body.provider not in ("ollama", "anthropic") and not body.endpoint_url:
        raise HTTPException(
            status_code=422,
            detail=f"provider {body.provider!r} needs endpoint_url — bring-your-own-model "
            "providers have no default to fall back to",
        )
    pin = await ModelPinRepository(session).pin(
        role=body.role,
        provider=body.provider,
        model=body.model,
        digest=body.digest,
        pinned_by=body.pinned_by,
        changelog_note=body.changelog_note,
        pinned_at=datetime.now(UTC),
        endpoint_url=body.endpoint_url,
        credential_ref=body.credential_ref,
        eval_run_id=body.eval_run_id,
    )
    return ModelPinOut.model_validate(pin)


@router.post("/test", response_model=ProviderTestResultOut)
async def test_provider_connection(
    body: ProviderTestRequest, settings: SettingsDep
) -> ProviderTestResultOut:
    resolved_key = resolve_credential(body.credential_ref)
    result = await test_connection(
        provider=body.provider,
        model=body.model,
        base_url=body.endpoint_url
        or (settings.llm_base_url if body.provider == "ollama" else None),
        api_key=resolved_key
        or (settings.anthropic_api_key if body.provider == "anthropic" else None),
    )
    return ProviderTestResultOut(
        ok=result.ok,
        latency_ms=result.latency_ms,
        detail=result.detail,
        model_found=result.model_found,
    )
