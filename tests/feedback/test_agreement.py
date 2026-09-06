from __future__ import annotations

from kiyooo.feedback.agreement import AgreementRecord, compute_agreement


def test_agreement_rate_computed_per_key() -> None:
    records = [
        AgreementRecord("exposed-database", "claude-sonnet-5", "v3", agreed=True),
        AgreementRecord("exposed-database", "claude-sonnet-5", "v3", agreed=True),
        AgreementRecord("exposed-database", "claude-sonnet-5", "v3", agreed=False),
    ]
    stats = compute_agreement(records)
    key = ("exposed-database", "claude-sonnet-5", "v3")
    assert stats[key].total == 3
    assert stats[key].agreed == 2
    assert stats[key].rate == 2 / 3


def test_different_models_are_separate_keys() -> None:
    records = [
        AgreementRecord("exposed-database", "model-a", "v1", agreed=True),
        AgreementRecord("exposed-database", "model-b", "v1", agreed=False),
    ]
    stats = compute_agreement(records)
    assert len(stats) == 2
    assert stats[("exposed-database", "model-a", "v1")].rate == 1.0
    assert stats[("exposed-database", "model-b", "v1")].rate == 0.0


def test_empty_records_returns_empty_dict() -> None:
    assert compute_agreement([]) == {}
