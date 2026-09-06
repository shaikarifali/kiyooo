from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from kiyooo.db.models import ModuleToggle
from kiyooo.db.repo.base import Repository

# Kept in sync with the module_key values seeded by 0018_module_toggles.py
# and the pages under web/app/ — cloud, containers, repos, mobile,
# attack_paths. Not an enum on the model itself: a fixed Python set here is
# enough to seed and validate against, and doesn't need its own migration
# every time a domain page is added.
MODULE_KEYS = ("cloud", "containers", "repos", "mobile", "attack_paths")


class ModuleToggleRepository(Repository[ModuleToggle]):
    model = ModuleToggle

    async def list_all(self, limit: int = 100) -> list[ModuleToggle]:
        result = await self._session.execute(select(ModuleToggle).order_by(ModuleToggle.module_key))
        return list(result.scalars().all())

    async def set_enabled(
        self, module_key: str, *, enabled: bool, updated_at: datetime
    ) -> ModuleToggle:
        """Idempotent upsert-by-key — a module that predates a fresh install's
        migration seed (or was somehow never seeded) still gets a row here
        rather than a 404, since this is a UI convenience, not an aggregate
        the caller is expected to have created first.
        """
        toggle = await self.get(module_key)
        if toggle is None:
            toggle = ModuleToggle(module_key=module_key, enabled=enabled, updated_at=updated_at)
            return await self.add(toggle)
        toggle.enabled = enabled
        toggle.updated_at = updated_at
        await self._session.flush()
        return toggle
