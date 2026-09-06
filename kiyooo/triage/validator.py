"""Anti-hallucination cross-checks + identifier verification,
run after every LLM call, deterministically — no model in this loop.

Identifier verification's "resolvable in NVD/OSV" and "CVSS pulled from
NVD" checks need a live network call — `fetch_cve_from_nvd` makes it, and
nothing in the test suite calls it (same treatment as `enrich/kev.py`'s
`fetch_kev_catalog`). `verify_identifiers` takes an optional `nvd_lookup`
callable; without one, CVE/CWE/CVSS checks fall back to what's derivable
from the bundle alone (evidence-presence, cross-referencing claims within
the same verdict) rather than the full NVD authority check the design doc
describes — a documented partial mode, not a silent gap.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from kiyooo.db.models import IdentifierAuthority, IdentifierKind, IdentifierStatus
from kiyooo.triage.schema import VerdictSchema

if TYPE_CHECKING:
    import httpx

_CONFIDENCE_DOWNGRADE_THRESHOLD = 0.95
_MIN_CITATIONS_FOR_HIGH_CONFIDENCE = 2
_DOWNGRADED_CONFIDENCE = 0.7

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
_CVSS_PATTERN = re.compile(r"CVSS:3\.[01](?:/[A-Z]{1,2}:[A-Z])+", re.IGNORECASE)
_VERSION_PATTERN = re.compile(r"\b\d+\.\d+(?:\.\d+){0,2}\b")
_HOSTNAME_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_REFUSAL_PHRASES = (
    "i can't help",
    "i cannot help",
    "i can't assist",
    "i cannot assist",
    "i'm not able to",
    "i am not able to",
    "against my guidelines",
    "i won't be able to",
    "unable to comply",
)


# --------------------------------------------------------------------------- #
# schema / citation validation (§4.3 step 4)
# --------------------------------------------------------------------------- #


def _evidence_items(bundle: dict[str, object]) -> list[dict[str, object]]:
    evidence = bundle.get("evidence", [])
    if not isinstance(evidence, list):
        return []
    return [item for item in evidence if isinstance(item, dict)]


def validate_schema(
    raw_content: dict[str, object] | None,
) -> tuple[VerdictSchema | None, str | None]:
    if raw_content is None:
        return None, "no structured content returned"
    try:
        return VerdictSchema.model_validate(raw_content), None
    except Exception as exc:  # noqa: BLE001 -- surfaced as retry-with-error-text, not a crash
        return None, str(exc)


def find_missing_citations(verdict: VerdictSchema, bundle: dict[str, object]) -> list[str]:
    known_ids = {str(item["id"]) for item in _evidence_items(bundle)}
    return [c for c in verdict.citations if c not in known_ids]


def looks_like_refusal(raw_text: str) -> bool:
    lowered = raw_text.lower()
    return any(phrase in lowered for phrase in _REFUSAL_PHRASES)


# --------------------------------------------------------------------------- #
# cross-checks (§4.4)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CrossCheckResult:
    verdict: VerdictSchema
    forced_needs_human: bool
    force_escalation: bool
    notes: list[str] = field(default_factory=list)


def run_cross_checks(verdict: VerdictSchema, bundle: dict[str, object]) -> CrossCheckResult:
    notes: list[str] = []
    forced_needs_human = False
    force_escalation = False
    result_verdict = verdict

    evidence_kinds = {str(item["kind"]) for item in _evidence_items(bundle)}
    if verdict.exploitability.internet_reachable and not (
        "http_response" in evidence_kinds or "port_banner" in evidence_kinds
    ):
        forced_needs_human = True
        notes.append(
            "verdict claims internet_reachable=true with no probe evidence "
            "(http_response/port_banner) in the bundle"
        )

    finding = bundle.get("finding", {})
    raw_severity = finding.get("raw_severity") if isinstance(finding, dict) else None
    if verdict.verdict == "false_positive" and raw_severity == "critical":
        force_escalation = True
        forced_needs_human = True
        notes.append("false_positive on a critical base severity — never auto-buried")

    if (
        verdict.confidence > _CONFIDENCE_DOWNGRADE_THRESHOLD
        and len(verdict.citations) < _MIN_CITATIONS_FOR_HIGH_CONFIDENCE
    ):
        result_verdict = verdict.model_copy(update={"confidence": _DOWNGRADED_CONFIDENCE})
        notes.append(
            f"confidence {verdict.confidence} with fewer than "
            f"{_MIN_CITATIONS_FOR_HIGH_CONFIDENCE} citations — downgraded to "
            f"{_DOWNGRADED_CONFIDENCE}"
        )

    return CrossCheckResult(
        verdict=result_verdict,
        forced_needs_human=forced_needs_human,
        force_escalation=force_escalation,
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# identifier verification (§4.4)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class NvdCveRecord:
    cve_id: str
    cvss_vector: str | None
    cwe_ids: list[str]


NvdLookup = Callable[[str], Awaitable["NvdCveRecord | None"]]


@dataclass(frozen=True, slots=True)
class IdentifierCheckResult:
    kind: IdentifierKind
    claimed_value: str
    resolved: bool
    authority: IdentifierAuthority | None
    resolved_value: str | None
    status: IdentifierStatus


def _bundle_text_blob(bundle: dict[str, object]) -> str:
    parts: list[str] = []
    for item in _evidence_items(bundle):
        parts.append(str(item.get("summary", "")))
        parts.append(str(item.get("content", "")))
    return "\n".join(parts)


def extract_claimed_identifiers(verdict: VerdictSchema) -> dict[IdentifierKind, list[str]]:
    text = " ".join(
        [
            verdict.reasoning,
            verdict.exploitability.realistic_attack_path,
            verdict.business_impact_hypothesis,
        ]
    )
    return {
        IdentifierKind.CVE: sorted({m.upper() for m in _CVE_PATTERN.findall(text)}),
        IdentifierKind.CWE: sorted({m.upper() for m in _CWE_PATTERN.findall(text)}),
        IdentifierKind.CVSS_VECTOR: sorted(set(_CVSS_PATTERN.findall(text))),
        IdentifierKind.VERSION: sorted(set(_VERSION_PATTERN.findall(text))),
        IdentifierKind.HOSTNAME: sorted(
            set(_HOSTNAME_PATTERN.findall(text)) | set(_IP_PATTERN.findall(text))
        ),
    }


async def verify_identifiers(
    verdict: VerdictSchema,
    bundle: dict[str, object],
    *,
    known_identities: set[str] | None = None,
    nvd_lookup: NvdLookup | None = None,
) -> list[IdentifierCheckResult]:
    claimed = extract_claimed_identifiers(verdict)
    evidence_text = _bundle_text_blob(bundle)
    asset = bundle.get("asset", {})
    asset_value = str(asset.get("value", "")) if isinstance(asset, dict) else ""
    identities = (known_identities or set()) | {asset_value}

    results: list[IdentifierCheckResult] = []
    verified_cves: dict[str, NvdCveRecord] = {}

    for cve_id in claimed[IdentifierKind.CVE]:
        in_evidence = cve_id in evidence_text.upper()
        nvd_record = await nvd_lookup(cve_id) if nvd_lookup is not None else None
        if nvd_record is not None:
            verified_cves[cve_id] = nvd_record
        if nvd_lookup is None:
            resolved = in_evidence
            status = IdentifierStatus.VERIFIED if resolved else IdentifierStatus.HALLUCINATED
            authority = IdentifierAuthority.EVIDENCE if resolved else None
        elif not in_evidence:
            resolved = False
            status = IdentifierStatus.HALLUCINATED
            authority = None
        elif nvd_record is None:
            resolved = False
            status = IdentifierStatus.NOT_FOUND
            authority = None
        else:
            resolved = True
            status = IdentifierStatus.VERIFIED
            authority = IdentifierAuthority.NVD
        results.append(
            IdentifierCheckResult(
                kind=IdentifierKind.CVE,
                claimed_value=cve_id,
                resolved=resolved,
                authority=authority,
                resolved_value=cve_id if resolved else None,
                status=status,
            )
        )

    for cwe_id in claimed[IdentifierKind.CWE]:
        matching_cve = next((rec for rec in verified_cves.values() if cwe_id in rec.cwe_ids), None)
        resolved = matching_cve is not None
        results.append(
            IdentifierCheckResult(
                kind=IdentifierKind.CWE,
                claimed_value=cwe_id,
                resolved=resolved,
                authority=IdentifierAuthority.NVD if resolved else None,
                resolved_value=cwe_id if resolved else None,
                status=IdentifierStatus.VERIFIED if resolved else IdentifierStatus.HALLUCINATED,
            )
        )

    for cvss in claimed[IdentifierKind.CVSS_VECTOR]:
        matching_cve = next(
            (rec for rec in verified_cves.values() if rec.cvss_vector == cvss), None
        )
        resolved = matching_cve is not None
        results.append(
            IdentifierCheckResult(
                kind=IdentifierKind.CVSS_VECTOR,
                claimed_value=cvss,
                resolved=resolved,
                authority=IdentifierAuthority.NVD if resolved else None,
                resolved_value=cvss if resolved else None,
                status=IdentifierStatus.VERIFIED if resolved else IdentifierStatus.HALLUCINATED,
            )
        )

    for version in claimed[IdentifierKind.VERSION]:
        resolved = version in evidence_text
        results.append(
            IdentifierCheckResult(
                kind=IdentifierKind.VERSION,
                claimed_value=version,
                resolved=resolved,
                authority=IdentifierAuthority.EVIDENCE if resolved else None,
                resolved_value=version if resolved else None,
                status=IdentifierStatus.VERIFIED if resolved else IdentifierStatus.MISMATCH,
            )
        )

    for hostname in claimed[IdentifierKind.HOSTNAME]:
        resolved = hostname in identities or hostname in evidence_text
        results.append(
            IdentifierCheckResult(
                kind=IdentifierKind.HOSTNAME,
                claimed_value=hostname,
                resolved=resolved,
                authority=IdentifierAuthority.EVIDENCE if resolved else None,
                resolved_value=hostname if resolved else None,
                status=IdentifierStatus.VERIFIED if resolved else IdentifierStatus.HALLUCINATED,
            )
        )

    return results


async def fetch_cve_from_nvd(client: httpx.AsyncClient, cve_id: str) -> NvdCveRecord | None:
    """Live network call — public, unauthenticated (NVD's own low-volume
    tier needs no API key). Nothing in the test suite calls this; only
    `verify_identifiers`'s pure evidence-presence path is exercised there.
    """
    resp = await client.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id},
        timeout=30.0,
    )
    resp.raise_for_status()
    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get("cve", {})
    metrics = cve.get("metrics", {})
    cvss_metrics = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    cvss_vector = cvss_metrics[0]["cvssData"]["vectorString"] if cvss_metrics else None

    cwe_ids = [
        description["value"]
        for weakness in cve.get("weaknesses", [])
        for description in weakness.get("description", [])
        if str(description.get("value", "")).startswith("CWE-")
    ]
    return NvdCveRecord(cve_id=cve_id, cvss_vector=cvss_vector, cwe_ids=cwe_ids)
