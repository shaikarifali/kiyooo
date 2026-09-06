"""FastAPI dependencies. One engine for the app's lifetime (built in
`app.py`'s lifespan handler and stashed on `app.state`), one `AsyncSession`
per request via `db/session.py`'s own `session_scope` — the same
transaction-per-unit-of-work pattern every CLI command already uses.

No auth dependency exists yet — RBAC/SSO is Stage 11's explicitly-deferred
item (no IdP to build safely against in this environment). This API is for
a trusted network until that lands; don't expose it publicly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from kiyooo.config import OrgContext, Settings
from kiyooo.db.session import session_scope


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    session_factory = request.app.state.session_factory
    async with session_scope(session_factory) as session:
        yield session


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_org_context(request: Request) -> OrgContext:
    org_context: OrgContext = request.app.state.org_context
    return org_context


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
OrgContextDep = Annotated[OrgContext, Depends(get_org_context)]
