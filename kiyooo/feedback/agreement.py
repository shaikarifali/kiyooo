"""feedback/agreement.py — Stage 8's agreement dashboard:
model/human agreement rate per category, per model, per prompt_version.
Categories with low agreement are the ones whose `triage_hints` need
rewriting. Pure — the caller joins `HumanReview.agreed_with_model` (already
captured at review time, see `kiyooo review`) against the finding's latest
`Verdict.model`/`prompt_version` and hands over flat records.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AgreementRecord:
    category_id: str
    model: str
    prompt_version: str
    agreed: bool


@dataclass(frozen=True, slots=True)
class AgreementStats:
    total: int
    agreed: int

    @property
    def rate(self) -> float:
        return self.agreed / self.total if self.total else 0.0


def compute_agreement(
    records: list[AgreementRecord],
) -> dict[tuple[str, str, str], AgreementStats]:
    stats: dict[tuple[str, str, str], list[int]] = {}
    for record in records:
        key = (record.category_id, record.model, record.prompt_version)
        counts = stats.setdefault(key, [0, 0])
        counts[0] += 1
        if record.agreed:
            counts[1] += 1
    return {
        key: AgreementStats(total=total, agreed=agreed) for key, (total, agreed) in stats.items()
    }
