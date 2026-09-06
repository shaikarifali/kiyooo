"""Runs a labeled corpus against one provider/model directly — the bulk
pass's shape only (no cache, no escalation, no identifier verification).
This measures one model's raw adjudication accuracy, which is what the
eval harness exists to measure; it deliberately doesn't run the full
`triage/agent.py` pipeline.

CLAUDE.md: "The eval harness ... is the only thing that calls a real
model, and it is run deliberately, not in CI by default." Nothing in
`tests/` imports this module for that reason — `kiyooo eval run` (cli.py)
is the only caller.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import Finding, FindingDetector, Severity
from kiyooo.detect.cases import build_asset, build_evidence
from kiyooo.eval.metrics import EvalResult
from kiyooo.llm.cost import calculate_cost
from kiyooo.llm.provider import Message
from kiyooo.skills.loader import select_skills_for_category
from kiyooo.triage.bundler import build_bundle, bundle_canonical_json
from kiyooo.triage.prompts import load_adjudicate_prompt
from kiyooo.triage.schema import verdict_json_schema
from kiyooo.triage.validator import validate_schema

if TYPE_CHECKING:
    from kiyooo.config import CategoryDefinition
    from kiyooo.eval.corpus import EvalCorpus, LabeledCase
    from kiyooo.llm.provider import LlmProvider
    from kiyooo.skills.loader import Skill


def _synthetic_finding(
    case: LabeledCase, category: CategoryDefinition, asset_id: uuid.UUID
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=asset_id,
        category_id=category.id,
        raw_severity=Severity(category.severity_base),
        title=category.name,
        description=None,
        detector=FindingDetector.RULE,
        detector_ref=f"eval:{case.id}",
        fingerprint=f"eval-{case.id}",
        cluster_id=uuid.uuid4(),
        first_seen=now,
        last_seen=now,
    )


async def run_eval(
    corpus: EvalCorpus,
    categories: dict[str, CategoryDefinition],
    provider: LlmProvider,
    model: str,
    *,
    provider_name: str,
    org_name: str,
    skills: list[Skill] | None = None,
) -> list[EvalResult]:
    schema = verdict_json_schema()
    system_prompt = load_adjudicate_prompt(org_name=org_name)
    results: list[EvalResult] = []

    for case in corpus.cases:
        category = categories.get(case.category_id)
        if category is None:
            continue

        asset = build_asset(case.asset)
        evidence = build_evidence(asset.id, case.evidence)
        finding = _synthetic_finding(case, category, asset.id)

        selected_skills = select_skills_for_category(skills or [], category)
        bundle = build_bundle(
            finding,
            category,
            asset,
            evidence,
            controls_detected=[],
            change_events=[],
            similar_past_decisions=[],
            is_new_since_last_scan=True,
            is_hosted_call=category.redaction_profile != "local_only",
            skills=selected_skills,
        )
        messages = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=bundle_canonical_json({"evidence_bundle": bundle})),
        ]

        start = time.monotonic()
        response = await provider.complete(messages, schema=schema, model=model)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        verdict, _error = validate_schema(response.content)
        predicted_verdict = verdict.verdict if verdict else "needs_human"
        predicted_severity = verdict.adjusted_severity if verdict else case.human_severity

        results.append(
            EvalResult(
                case_id=case.id,
                predicted_verdict=predicted_verdict,
                predicted_severity=predicted_severity,
                human_verdict=case.human_verdict,
                human_severity=case.human_severity,
                cost_usd=calculate_cost(
                    provider_name,
                    response.model or model,
                    tokens_in=response.tokens_in,
                    tokens_out=response.tokens_out,
                ),
                latency_ms=response.latency_ms or elapsed_ms,
            )
        )

    return results
