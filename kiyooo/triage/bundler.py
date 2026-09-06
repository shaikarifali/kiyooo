"""Evidence bundle assembly — the LLM's entire view of a
finding. Every evidence item gets a stable `ev_N` id *within this bundle*
(not the same as `Evidence.id`, which is scan-scoped) — that's what the
verdict's `citations` field and `triage/validator.py`'s citation-existence
check both key off.

Token budget is a rough character-count approximation (`chars // 4`), not a
real tokenizer — this project takes no tokenizer dependency, and the goal
is "stay well clear of the limit," not exact accounting. Evidence bodies
are middle-elided to fit; an evidence item linked to the finding is never
dropped entirely, only shrunk, down to a floor — the design's rule is
"truncate, never silently drop an evidence item cited by a rule."

Redaction happens here, not in the
provider layer: a `local_only` category must never reach this function
with `is_hosted_call=True` (the caller — `triage/agent.py` — is expected to
route it to a local provider only; this function still refuses as defense
in depth), and `headers_only` strips response/cert/banner bodies before a
hosted call, keeping only header-shaped metadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kiyooo.db.models import EvidenceKind

if TYPE_CHECKING:
    from kiyooo.config import CategoryDefinition
    from kiyooo.db.models import Asset, ChangeEvent, Control, Evidence, Finding
    from kiyooo.skills.loader import SelectedSkill

_DEFAULT_TOKEN_BUDGET = 12_000
_CHARS_PER_TOKEN = 4
_MIN_EVIDENCE_CHARS = 200
_ELISION_MARKER = "...[elided {n} chars]..."

_AVAILABLE_VERIFICATION_TOOLS = (
    "http_probe",
    "tls_handshake",
    "dns_resolve",
    "tcp_banner",
    "cert_chain",
    "nuclei_single",
)

# Fields kept when a category's redaction_profile is headers_only and the
# call is hosted-bound — everything else in content_inline is dropped.
_HEADER_SAFE_FIELDS: dict[EvidenceKind, frozenset[str]] = {
    EvidenceKind.HTTP_RESPONSE: frozenset(
        {"status_code", "header", "title", "tech", "url", "host"}
    ),
    EvidenceKind.TLS_CERT: frozenset(
        {"subject_cn", "issuer_cn", "not_after", "serial_number", "host", "port"}
    ),
    EvidenceKind.PORT_BANNER: frozenset({"port", "protocol", "host"}),
    EvidenceKind.NUCLEI_RESULT: frozenset({"template-id", "info", "host", "matched-at"}),
}


class RedactionViolation(Exception):
    """A `local_only` category's evidence was about to be bundled for a
    hosted-provider call. This should never happen if the caller checked
    `category.redaction_profile` before choosing a provider — this
    exception is the defense-in-depth backstop, not the primary control.
    """


@dataclass(frozen=True, slots=True)
class SimilarPastDecision:
    finding_summary: str
    human_verdict: str
    rationale: str


def _redact_content(
    kind: EvidenceKind, content: dict[str, object], profile: str
) -> dict[str, object]:
    if profile != "headers_only":
        return content
    keep = _HEADER_SAFE_FIELDS.get(kind)
    if keep is None:
        return content
    return {k: v for k, v in content.items() if k in keep}


def _summarize(evidence: Evidence) -> str:
    record = evidence.content_inline or {}
    if evidence.kind == EvidenceKind.HTTP_RESPONSE:
        return f"HTTP {record.get('status_code', '?')} — {record.get('title', '(no title)')}"
    if evidence.kind == EvidenceKind.PORT_BANNER:
        return f"port {record.get('port', '?')}/{record.get('protocol', 'tcp')} open"
    if evidence.kind == EvidenceKind.TLS_CERT:
        return f"cert CN={record.get('subject_cn', '?')}, expires {record.get('not_after', '?')}"
    if evidence.kind == EvidenceKind.NUCLEI_RESULT:
        return f"nuclei template {record.get('template-id', '?')} matched"
    return f"{evidence.kind.value} evidence from {evidence.source_tool}"


def _elide_middle(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    marker_len_estimate = len(_ELISION_MARKER.format(n=len(text)))
    keep = max(max_chars - marker_len_estimate, _MIN_EVIDENCE_CHARS // 2)
    head_len = keep // 2
    tail_len = keep - head_len
    elided = len(text) - head_len - tail_len
    return text[:head_len] + _ELISION_MARKER.format(n=elided) + text[len(text) - tail_len :]


def _build_evidence_entries(
    evidence: list[Evidence],
    *,
    category: CategoryDefinition,
    is_hosted_call: bool,
    content_char_budget: int,
) -> list[dict[str, object]]:
    if category.redaction_profile == "local_only" and is_hosted_call:
        raise RedactionViolation(
            f"category {category.id!r} is redaction_profile=local_only — refusing to "
            "build a bundle for a hosted-provider call"
        )
    profile = category.redaction_profile if is_hosted_call else "full"

    per_item_budget = max(content_char_budget // max(len(evidence), 1), _MIN_EVIDENCE_CHARS)
    entries: list[dict[str, object]] = []
    for i, item in enumerate(evidence, start=1):
        content = _redact_content(item.kind, item.content_inline or {}, profile)
        content_json = json.dumps(content, sort_keys=True, default=str)
        entries.append(
            {
                "id": f"ev_{i}",
                "kind": item.kind.value,
                "summary": _summarize(item),
                "content": _elide_middle(content_json, per_item_budget),
                "injection_suspected": item.injection_suspected,
            }
        )
    return entries


def build_bundle(
    finding: Finding,
    category: CategoryDefinition,
    asset: Asset,
    evidence: list[Evidence],
    *,
    controls_detected: list[Control],
    change_events: list[ChangeEvent],
    similar_past_decisions: list[SimilarPastDecision],
    is_new_since_last_scan: bool,
    is_hosted_call: bool,
    accepted_risk_notes: list[str] | None = None,
    skills: list[SelectedSkill] | None = None,
    token_budget: int = _DEFAULT_TOKEN_BUDGET,
) -> dict[str, object]:
    char_budget = token_budget * _CHARS_PER_TOKEN
    # Fixed sections (finding/asset/category/controls/context) come out of
    # the budget first; whatever's left is what evidence bodies share.
    fixed_overhead_chars = 2_000
    evidence_char_budget = max(char_budget - fixed_overhead_chars, _MIN_EVIDENCE_CHARS)

    evidence_entries = _build_evidence_entries(
        evidence,
        category=category,
        is_hosted_call=is_hosted_call,
        content_char_budget=evidence_char_budget,
    )

    return {
        "bundle_version": "1.0",
        "finding": {
            "id": str(finding.id),
            "category": category.model_dump(mode="json"),
            "title": finding.title,
            "raw_severity": finding.raw_severity.value,
            "detector": finding.detector.value,
        },
        "asset": {
            "id": str(asset.id),
            "type": asset.type.value,
            "value": asset.value,
            "attributes": asset.attributes,
            "first_seen": asset.first_seen.isoformat(),
        },
        "evidence": evidence_entries,
        "controls_detected": [
            {
                "id": control.control_id,
                "evidence_id": control.evidence_id,
                "detected_by": control.detected_by,
            }
            for control in controls_detected
        ],
        "org_context": {
            # environments/known_waf_asns/corporate_egress have no
            # org-context config surface yet — populated empty rather than
            # guessed at, same treatment as Stage 3's documented gaps.
            "environments": {},
            "known_waf_asns": [],
            "corporate_egress": [],
            "accepted_risks_for_this_asset": accepted_risk_notes or [],
        },
        "similar_past_decisions": [
            {
                "finding_summary": d.finding_summary,
                "human_verdict": d.human_verdict,
                "rationale": d.rationale,
            }
            for d in similar_past_decisions[:3]
        ],
        "change_context": {
            "is_new_since_last_scan": is_new_since_last_scan,
            "related_change_events": [event.kind.value for event in change_events],
        },
        "available_verification_tools": list(_AVAILABLE_VERIFICATION_TOOLS),
        # Stage 9: org-specific playbooks, selected by
        # `skills/loader.py` against this category before the bundle was
        # built — knowledge injection only, no executable capability.
        "skills": [{"name": s.name, "body": s.body} for s in (skills or [])],
    }


def bundle_canonical_json(bundle: dict[str, object]) -> str:
    """Stable serialization for `triage/cache.py`'s `input_hash` — same
    bundle contents in a different key order must hash identically.
    """
    return json.dumps(bundle, sort_keys=True, default=str)
