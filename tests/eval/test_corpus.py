from __future__ import annotations

from pathlib import Path

from kiyooo.db.models import AssetType, EvidenceKind
from kiyooo.detect.cases import CaseAsset, CaseEvidence
from kiyooo.eval.corpus import LabeledCase, load_corpus, save_case


def _case(case_id: str = "human-review-1") -> LabeledCase:
    return LabeledCase(
        id=case_id,
        category_id="exposed-database",
        asset=CaseAsset(type=AssetType.TCP_SERVICE, value="10.0.0.5:3306"),
        evidence=[CaseEvidence(kind=EvidenceKind.PORT_BANNER, content={"port": 3306})],
        human_verdict="false_positive",
        human_severity="critical",
        notes="internal-only via VPN",
    )


def test_save_case_round_trips_through_load_corpus(tmp_path: Path) -> None:
    case = _case()
    path = save_case(case, tmp_path)
    assert path == tmp_path / "human-review-1.yaml"

    corpus = load_corpus(tmp_path)
    assert len(corpus.cases) == 1
    loaded = corpus.cases[0]
    assert loaded.id == case.id
    assert loaded.category_id == case.category_id
    assert loaded.human_verdict == "false_positive"
    assert loaded.notes == "internal-only via VPN"


def test_save_case_overwrites_same_id(tmp_path: Path) -> None:
    save_case(_case(), tmp_path)
    updated = _case()
    updated = updated.model_copy(update={"notes": "revised rationale"})
    save_case(updated, tmp_path)

    corpus = load_corpus(tmp_path)
    assert len(corpus.cases) == 1
    assert corpus.cases[0].notes == "revised rationale"


def test_save_case_creates_missing_directory(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "nested" / "corpus"
    save_case(_case(), corpus_dir)
    assert (corpus_dir / "human-review-1.yaml").exists()
