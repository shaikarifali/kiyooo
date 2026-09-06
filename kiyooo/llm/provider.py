"""LLM provider abstraction. Every provider is a thin
REST wrapper over `httpx` — no vendor SDKs, so the whole layer is auditable
in one place and testable offline via `httpx.MockTransport`, consistent
with this project's "no live network calls in the test suite" rule.

Evidence never enters the system prompt. This ABC takes
that on faith from its caller — `complete()` sends whatever `messages` it's
given verbatim; message construction discipline lives in `triage/bundler.py`
and `triage/agent.py`, not here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True, slots=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True, slots=True)
class LlmResponse:
    # Parsed structured output matching the requested schema. `None` when
    # `refused` is True, or when the provider's response couldn't be
    # parsed against the schema at all (distinct from a validation
    # failure on an otherwise-parseable response, which is
    # `triage/validator.py`'s job to catch, not the provider's).
    content: dict[str, object] | None
    raw_text: str
    model: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    refused: bool = False
    refusal_reason: str | None = None


class ProviderError(Exception):
    """A provider call failed for a reason that isn't a model refusal —
    network error, auth failure, rate limit, malformed request. Distinct
    from `LlmResponse.refused`, which is a *successful* call the model
    declined to answer.
    """


class LlmProvider(ABC):
    name: str

    @abstractmethod
    async def complete(
        self,
        messages: list[Message],
        *,
        schema: dict[str, object],
        model: str,
        max_tokens: int = 4096,
        tools: list[dict[str, object]] | None = None,
    ) -> LlmResponse:
        """Structured-output completion. Implementations use the provider's
        native structured-output mechanism where one exists (Anthropic:
        forced tool-use with `schema` as the tool's `input_schema`; Ollama:
        the `format` field) rather than JSON-mode-and-hope. Retry-with-
        error-text is the caller's responsibility,
        not this method's — a provider makes one call and reports what it
        got.
        """
        ...

    @abstractmethod
    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        """One embedding vector per input text, same order. Powers
        `triage/memory.py`'s pgvector similarity search.
        """
        ...
