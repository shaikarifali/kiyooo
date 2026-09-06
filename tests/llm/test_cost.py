from __future__ import annotations

from kiyooo.llm.cost import calculate_cost, is_local_provider


def test_is_local_provider() -> None:
    assert is_local_provider("ollama") is True
    assert is_local_provider("vllm") is True
    assert is_local_provider("anthropic") is False


def test_local_provider_is_always_free() -> None:
    cost = calculate_cost("ollama", "llama3.1:8b", tokens_in=1_000_000, tokens_out=1_000_000)
    assert cost == 0.0


def test_known_hosted_model_uses_its_own_pricing() -> None:
    cost = calculate_cost("anthropic", "claude-sonnet-5", tokens_in=1_000_000, tokens_out=0)
    assert cost == 3.00


def test_unknown_hosted_model_uses_conservative_fallback() -> None:
    cost = calculate_cost("anthropic", "some-future-model", tokens_in=1_000_000, tokens_out=0)
    assert cost == 5.00


def test_cost_scales_with_token_count() -> None:
    cost = calculate_cost("anthropic", "claude-sonnet-5", tokens_in=500_000, tokens_out=200_000)
    assert cost == (500_000 / 1_000_000) * 3.00 + (200_000 / 1_000_000) * 15.00
