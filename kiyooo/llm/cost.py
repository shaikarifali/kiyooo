"""Per-model token pricing. Used by `llm/router.py`'s
per-run cost ceiling and stored on every `Verdict`/`LlmCallLog` row.

Local providers (Ollama, vLLM) are always free at the token level — their
cost is the hardware, which this project has no way to meter. Pricing
drifts; this table isn't the pricing authority, it's what this deployment
is configured to believe it pays. Update it when a provider changes
pricing, same discipline as any other pinned-artifact change.
"""

from __future__ import annotations

_LOCAL_PROVIDERS = frozenset({"ollama", "vllm"})

# USD per 1M tokens: (input, output).
_PRICING_PER_MILLION: dict[tuple[str, str], tuple[float, float]] = {
    ("anthropic", "claude-opus-5"): (15.00, 75.00),
    ("anthropic", "claude-sonnet-5"): (3.00, 15.00),
    ("anthropic", "claude-haiku-4-5-20251001"): (0.80, 4.00),
    ("openai", "gpt-4o"): (2.50, 10.00),
    ("openai", "gpt-4o-mini"): (0.15, 0.60),
}

# Conservative fallback for a hosted model this table doesn't list yet —
# better to overestimate spend than silently undercount it.
_DEFAULT_HOSTED_PRICE_PER_MILLION = (5.00, 15.00)


def is_local_provider(provider: str) -> bool:
    return provider in _LOCAL_PROVIDERS


def calculate_cost(provider: str, model: str, *, tokens_in: int, tokens_out: int) -> float:
    if provider in _LOCAL_PROVIDERS:
        return 0.0
    price_in, price_out = _PRICING_PER_MILLION.get(
        (provider, model), _DEFAULT_HOSTED_PRICE_PER_MILLION
    )
    return (tokens_in / 1_000_000) * price_in + (tokens_out / 1_000_000) * price_out
