from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from kiyooo.db.models import ModelPin, ModelPinRole
from kiyooo.db.repo.base import Repository


class ModelPinRepository(Repository[ModelPin]):
    model = ModelPin

    async def get_active(self, role: ModelPinRole) -> ModelPin | None:
        """The current pin for a role: not superseded by a later one. A
        model/prompt/digest bump is a pin *row*, never an update to an
        existing row — invariant #8 requires an eval re-run and a
        changelog entry per change, which only a new row can carry.
        """
        result = await self._session.execute(
            select(ModelPin)
            .where(ModelPin.role == role, ModelPin.superseded_by.is_(None))
            .order_by(ModelPin.pinned_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def list_active(self) -> list[ModelPin]:
        """One row per role (bulk/escalation/embedding) — whatever's
        currently active, roles with no pin yet simply absent (the caller
        falls back to `Settings` for those, same as `select_model` does).
        """
        result = await self._session.execute(
            select(ModelPin).where(ModelPin.superseded_by.is_(None)).order_by(ModelPin.role)
        )
        return list(result.scalars().all())

    async def pin(
        self,
        *,
        role: ModelPinRole,
        provider: str,
        model: str,
        digest: str,
        pinned_by: str,
        changelog_note: str,
        pinned_at: datetime,
        endpoint_url: str | None = None,
        credential_ref: str | None = None,
        eval_run_id: str | None = None,
    ) -> ModelPin:
        """A pin is always a new row — invariant #8: a model/digest change
        needs its own changelog entry, which an UPDATE would erase. The
        row it replaces (if any) gets `superseded_by` pointed at the new
        one, never deleted. `provider` is free text — `endpoint_url`/
        `credential_ref` are how a bring-your-own provider (anything but
        "ollama"/"anthropic") says where to call and which env var holds
        its key; both stay `None` for the two built-in providers, which
        have their own defaults.
        """
        previous = await self.get_active(role)
        new_pin = ModelPin(
            role=role,
            provider=provider,
            model=model,
            digest=digest,
            endpoint_url=endpoint_url,
            credential_ref=credential_ref,
            pinned_at=pinned_at,
            pinned_by=pinned_by,
            eval_run_id=eval_run_id,
            changelog_note=changelog_note,
            superseded_by=None,
        )
        await self.add(new_pin)
        if previous is not None:
            previous.superseded_by = new_pin.id
            await self._session.flush()
        return new_pin
