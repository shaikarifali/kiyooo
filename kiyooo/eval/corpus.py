"""Labeled corpus format for the eval harness (Stage 5: "a
labeled corpus (start with 100 hand-labeled findings from your own
scans)"). One file per case — reuses `detect/cases.py`'s `CaseAsset`/
`CaseEvidence` fixture shapes, since a labeled eval case and a category
test case are the same underlying thing: an asset + evidence + expected
outcome.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from kiyooo.detect.cases import CaseAsset, CaseEvidence

HumanVerdict = Literal["true_positive", "false_positive", "not_exploitable", "needs_human"]
HumanSeverity = Literal["critical", "high", "medium", "low", "info"]


class LabeledCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category_id: str
    asset: CaseAsset
    evidence: list[CaseEvidence] = []
    human_verdict: HumanVerdict
    human_severity: HumanSeverity
    notes: str | None = None


class EvalCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cases: list[LabeledCase] = []


def load_corpus(path: Path) -> EvalCorpus:
    cases: list[LabeledCase] = []
    for case_file in sorted(path.glob("*.yaml")):
        raw = yaml.safe_load(case_file.read_text(encoding="utf-8")) or {}
        cases.append(LabeledCase.model_validate(raw))
    return EvalCorpus(cases=cases)


def save_case(case: LabeledCase, corpus_dir: Path) -> Path:
    """Stage 8: "auto-add reviewed findings to the eval corpus"
    — one file per case, same layout `load_corpus` reads back. Overwrites
    on a repeat id (a second review of the same finding replaces its case
    rather than duplicating it).
    """
    corpus_dir.mkdir(parents=True, exist_ok=True)
    case_path = corpus_dir / f"{case.id}.yaml"
    case_path.write_text(
        yaml.safe_dump(case.model_dump(mode="json", exclude_none=True), sort_keys=False),
        encoding="utf-8",
    )
    return case_path
