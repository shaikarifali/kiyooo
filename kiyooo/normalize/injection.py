"""Prompt injection canary scan. Runs across every
evidence body at ingest — HTTP response bodies, page titles, TLS cert CN/
SAN fields, headers, service banners, JS content are all attacker-
controlled (whoever runs the scanned host wrote them). A hit sets
`Evidence.injection_suspected = true`, which `triage/validator.py` uses to
invert the triage default (§4.5.4): a finding whose bundle includes
flagged evidence can never auto-close on a `false_positive`/
`not_exploitable` verdict.

Deliberately biased toward false positives over false negatives — a
mismatched hit just forces a human to look at one more finding; a missed
hit lets an attacker suppress the finding about their own foothold. Pure
and fixture-tested — pattern matching only, no model call, no network.
"""

from __future__ import annotations

import base64
import binascii
import re

_DIRECT_ADDRESS_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(all\s+|)(previous|prior|above)\s+instructions?\b"),
    re.compile(r"(?i)\bdisregard\s+(all\s+|)(previous|prior|above)\s+instructions?\b"),
    re.compile(r"(?i)\byou\s+are\s+(now\s+|)an?\s+(ai|assistant|language\s+model|llm)\b"),
    re.compile(r"(?i)\bnew\s+instructions?\s*:"),
    re.compile(r"(?i)\bsystem\s*prompt\b"),
]

# "System:"/"Assistant:" at line start is a chat-transcript-shaped marker no
# ordinary web content has a reason to contain. Deliberately excludes bare
# "User:" — too common on profile pages/forums to be a useful signal alone.
_CHAT_ROLE_MARKER = re.compile(r"(?im)^\s*(system|assistant)\s*:\s*\S")

_IMPERATIVE_ADDRESS = re.compile(
    r"(?i)\b(assistant|claude|chatgpt|gpt|copilot)\s*[,:]?\s*(please\s+|)"
    r"(ignore|disregard|forget|mark|do\s+not|don't|stop|report|classify)\b"
)

_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_MAX_DECODE_DEPTH = 2


def _matches_direct_pattern(text: str) -> bool:
    return (
        any(pattern.search(text) for pattern in _DIRECT_ADDRESS_PATTERNS)
        or bool(_CHAT_ROLE_MARKER.search(text))
        or bool(_IMPERATIVE_ADDRESS.search(text))
    )


def _decode_base64_candidates(text: str) -> list[str]:
    decoded: list[str] = []
    for candidate in _BASE64_CANDIDATE.findall(text):
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded.append(raw.decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return decoded


def scan_text(text: str, *, _depth: int = 0) -> bool:
    """True if `text` itself, or a base64 blob decoded out of it (up to
    `_MAX_DECODE_DEPTH` layers, catching one level of obfuscation), matches
    a known injection pattern.
    """
    if not text:
        return False
    if _matches_direct_pattern(text):
        return True
    if _depth >= _MAX_DECODE_DEPTH:
        return False
    return any(scan_text(decoded, _depth=_depth + 1) for decoded in _decode_base64_candidates(text))


def _flatten_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _flatten_strings(v)]
    return []


def scan_evidence_content(content: dict[str, object] | None) -> bool:
    """Scans every string value anywhere in an `Evidence.content_inline`
    dict, however deeply nested — every adapter's raw tool output shape
    differs, so this doesn't assume which keys might carry attacker text.
    """
    if not content:
        return False
    return any(scan_text(text) for text in _flatten_strings(content))
