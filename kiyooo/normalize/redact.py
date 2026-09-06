"""Secret redaction at ingest (Stage 11, invariant #7: "Secrets
are redacted at ingest. Store type, location, and partial hash. Never a
live credential in plaintext evidence, logs, or tickets.").

Runs across every evidence body before it's ever persisted — the same
"scanned before storage, not at triage time" treatment
`normalize/injection.py`'s canary scan gets, and for the same reason: once
a secret is in `content_hash`/`content_inline`/object storage, it's in
backups, logs, and (via evidence citations) potentially a ticket body too.
Redact first, then hash/store — never the other way around.

Pure and fixture-tested — pattern matching only, no model call, no network.
Deliberately biased toward over-redaction: a false-positive redaction costs
a triager a moment's confusion reading `[REDACTED:...]`; a missed one is a
live credential in a ticket.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass

_PARTIAL_HASH_LEN = 12

# Ordered so a more specific pattern (e.g. a named provider's token shape)
# redacts before the generic catch-all gets a chance to — once a span is
# replaced with a `[REDACTED:...]` placeholder, later patterns see the
# placeholder text, not the original secret, so a span is never redacted
# twice under a less-specific label.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+]{16,})['\"]?"
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class RedactedSecret:
    secret_type: str
    partial_hash: str


def _partial_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:_PARTIAL_HASH_LEN]


def redact_text(text: str) -> tuple[str, list[RedactedSecret]]:
    found: list[RedactedSecret] = []

    def _make_replacer(secret_type: str) -> Callable[[re.Match[str]], str]:
        def _replace(match: re.Match[str]) -> str:
            value = match.group(0)
            partial = _partial_hash(value)
            found.append(RedactedSecret(secret_type=secret_type, partial_hash=partial))
            return f"[REDACTED:{secret_type}:{partial}]"

        return _replace

    redacted = text
    for secret_type, pattern in _PATTERNS:
        redacted = pattern.sub(_make_replacer(secret_type), redacted)
    return redacted, found


def _walk(value: object, found: list[RedactedSecret]) -> object:
    if isinstance(value, str):
        redacted, hits = redact_text(value)
        found.extend(hits)
        return redacted
    if isinstance(value, dict):
        return {k: _walk(v, found) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, found) for v in value]
    return value


def redact_content(content: dict[str, object]) -> tuple[dict[str, object], list[RedactedSecret]]:
    """Recursively redacts secret-shaped strings anywhere in an evidence
    `content_inline` dict — response bodies, headers, and banners can all
    carry a live credential, not just an obvious `"secret"` field.
    """
    found: list[RedactedSecret] = []
    redacted = _walk(content, found)
    assert isinstance(redacted, dict)  # content is always a dict; _walk preserves the type
    return redacted, found
