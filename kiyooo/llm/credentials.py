"""`ModelPin.credential_ref` resolution — shared by the CLI (building a
real provider to run triage with) and the API (the "Test connection"
button). One place, so the two can never disagree on what a
`credential_ref` string means.
"""

from __future__ import annotations

import os

from kiyooo.llm.provider import ProviderError


def resolve_credential(credential_ref: str | None) -> str | None:
    """`credential_ref` is a pointer, never a raw key (invariant #6/#7) —
    `"env:VAR_NAME"` is the only scheme supported today, matching Part D
    §7's own example exactly. `None` in, `None` out — a provider with no
    credential configured is a normal, valid state (a local server with
    no auth in front of it), not an error on its own.
    """
    if not credential_ref:
        return None
    if credential_ref.startswith("env:"):
        return os.environ.get(credential_ref.removeprefix("env:"))
    raise ProviderError(
        f"unsupported credential_ref scheme: {credential_ref!r} — only 'env:VAR_NAME' is supported"
    )
