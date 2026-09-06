from __future__ import annotations

from kiyooo.db.models import IdentifierKind, IdentifierStatus
from kiyooo.triage.schema import VerdictSchema
from kiyooo.triage.validator import (
    NvdCveRecord,
    extract_claimed_identifiers,
    find_missing_citations,
    looks_like_refusal,
    run_cross_checks,
    validate_schema,
    verify_identifiers,
)

_VALID_PAYLOAD: dict[str, object] = {
    "verdict": "true_positive",
    "confidence": 0.9,
    "adjusted_severity": "high",
    "reasoning": "Reachable and unauthenticated [ev_1].",
    "citations": ["ev_1"],
    "exploitability": {
        "internet_reachable": True,
        "authentication_required": False,
        "preconditions": [],
        "realistic_attack_path": "Direct connection from the internet.",
    },
    "compensating_controls_considered": [],
    "business_impact_hypothesis": "Could expose customer data.",
    "remediation": {
        "summary": "Restrict to VPN.",
        "steps": [],
        "verification": "Re-scan and confirm closed.",
        "estimated_effort": "small",
    },
    "requires_verification": [],
}


def _verdict(**overrides: object) -> VerdictSchema:
    payload = dict(_VALID_PAYLOAD)
    payload.update(overrides)
    return VerdictSchema.model_validate(payload)


def _bundle(
    evidence: list[dict[str, object]],
    *,
    raw_severity: str = "high",
    asset_value: str = "10.0.0.5:3306",
) -> dict[str, object]:
    return {
        "finding": {"raw_severity": raw_severity},
        "asset": {"value": asset_value},
        "evidence": evidence,
    }


# --------------------------------------------------------------------------- #
# schema / citations / refusal
# --------------------------------------------------------------------------- #


def test_validate_schema_none_content() -> None:
    verdict, error = validate_schema(None)
    assert verdict is None
    assert error is not None


def test_validate_schema_valid() -> None:
    verdict, error = validate_schema(_VALID_PAYLOAD)
    assert verdict is not None
    assert error is None


def test_validate_schema_invalid_returns_error_text() -> None:
    verdict, error = validate_schema({"verdict": "not-a-real-value"})
    assert verdict is None
    assert error is not None


def test_find_missing_citations() -> None:
    verdict = _verdict(citations=["ev_1", "ev_99"])
    bundle = _bundle([{"id": "ev_1", "kind": "http_response"}])
    assert find_missing_citations(verdict, bundle) == ["ev_99"]


def test_find_missing_citations_all_present() -> None:
    verdict = _verdict(citations=["ev_1"])
    bundle = _bundle([{"id": "ev_1", "kind": "http_response"}])
    assert find_missing_citations(verdict, bundle) == []


def test_looks_like_refusal_true() -> None:
    assert looks_like_refusal("I can't help assess this exploit.") is True


def test_looks_like_refusal_false() -> None:
    assert looks_like_refusal("The service is reachable and unauthenticated.") is False


# --------------------------------------------------------------------------- #
# cross-checks
# --------------------------------------------------------------------------- #


def test_internet_reachable_claim_without_probe_evidence_forces_human() -> None:
    verdict = _verdict()  # exploitability.internet_reachable=True from default payload
    bundle = _bundle([{"id": "ev_1", "kind": "dns_record"}])
    result = run_cross_checks(verdict, bundle)
    assert result.forced_needs_human is True


def test_internet_reachable_claim_with_probe_evidence_not_forced() -> None:
    verdict = _verdict()
    bundle = _bundle([{"id": "ev_1", "kind": "http_response"}])
    result = run_cross_checks(verdict, bundle)
    assert result.forced_needs_human is False


def test_false_positive_on_critical_forces_escalation_and_human() -> None:
    verdict = _verdict(
        verdict="false_positive",
        exploitability={
            "internet_reachable": False,
            "authentication_required": False,
            "preconditions": [],
            "realistic_attack_path": "n/a",
        },
    )
    bundle = _bundle([{"id": "ev_1", "kind": "http_response"}], raw_severity="critical")
    result = run_cross_checks(verdict, bundle)
    assert result.forced_needs_human is True
    assert result.force_escalation is True


def test_high_confidence_low_citations_downgraded() -> None:
    verdict = _verdict(confidence=0.99, citations=["ev_1"])
    bundle = _bundle([{"id": "ev_1", "kind": "http_response"}])
    result = run_cross_checks(verdict, bundle)
    assert result.verdict.confidence == 0.7


def test_high_confidence_enough_citations_not_downgraded() -> None:
    verdict = _verdict(confidence=0.99, citations=["ev_1", "ev_2"])
    bundle = _bundle(
        [{"id": "ev_1", "kind": "http_response"}, {"id": "ev_2", "kind": "dns_record"}]
    )
    result = run_cross_checks(verdict, bundle)
    assert result.verdict.confidence == 0.99


# --------------------------------------------------------------------------- #
# identifier extraction + verification
# --------------------------------------------------------------------------- #


def test_extract_claimed_identifiers() -> None:
    verdict = _verdict(
        reasoning="Vulnerable to CVE-2023-12345 (CWE-89), version 1.2.3 confirmed via banner "
        "on host db.example.com [ev_1].",
    )
    claimed = extract_claimed_identifiers(verdict)
    assert claimed[IdentifierKind.CVE] == ["CVE-2023-12345"]
    assert claimed[IdentifierKind.CWE] == ["CWE-89"]
    assert "1.2.3" in claimed[IdentifierKind.VERSION]
    assert "db.example.com" in claimed[IdentifierKind.HOSTNAME]


async def test_verify_identifiers_cve_present_in_evidence_without_nvd() -> None:
    verdict = _verdict(reasoning="Vulnerable to CVE-2023-12345 [ev_1].")
    bundle = _bundle(
        [
            {
                "id": "ev_1",
                "kind": "nuclei_result",
                "summary": "",
                "content": "CVE-2023-12345 detected",
            }
        ]
    )
    results = await verify_identifiers(verdict, bundle)
    cve_result = next(r for r in results if r.kind == IdentifierKind.CVE)
    assert cve_result.status == IdentifierStatus.VERIFIED


async def test_verify_identifiers_cve_absent_from_evidence_is_hallucinated() -> None:
    verdict = _verdict(reasoning="Vulnerable to CVE-2099-99999 [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "nuclei_result", "summary": "", "content": "unrelated"}]
    )
    results = await verify_identifiers(verdict, bundle)
    cve_result = next(r for r in results if r.kind == IdentifierKind.CVE)
    assert cve_result.status == IdentifierStatus.HALLUCINATED


async def test_verify_identifiers_cve_with_nvd_lookup_not_found() -> None:
    async def nvd_lookup(cve_id: str) -> NvdCveRecord | None:
        return None

    verdict = _verdict(reasoning="Vulnerable to CVE-2023-12345 [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "nuclei_result", "summary": "", "content": "CVE-2023-12345"}]
    )
    results = await verify_identifiers(verdict, bundle, nvd_lookup=nvd_lookup)
    cve_result = next(r for r in results if r.kind == IdentifierKind.CVE)
    assert cve_result.status == IdentifierStatus.NOT_FOUND


async def test_verify_identifiers_cwe_verified_via_matching_cve() -> None:
    async def nvd_lookup(cve_id: str) -> NvdCveRecord | None:
        return NvdCveRecord(
            cve_id=cve_id,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_ids=["CWE-89"],
        )

    verdict = _verdict(reasoning="CVE-2023-12345 (CWE-89) [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "nuclei_result", "summary": "", "content": "CVE-2023-12345"}]
    )
    results = await verify_identifiers(verdict, bundle, nvd_lookup=nvd_lookup)
    cwe_result = next(r for r in results if r.kind == IdentifierKind.CWE)
    assert cwe_result.status == IdentifierStatus.VERIFIED


async def test_verify_identifiers_cwe_without_matching_cve_is_hallucinated() -> None:
    verdict = _verdict(reasoning="This is CWE-89 related [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "nuclei_result", "summary": "", "content": "nothing relevant"}]
    )
    results = await verify_identifiers(verdict, bundle)
    cwe_result = next(r for r in results if r.kind == IdentifierKind.CWE)
    assert cwe_result.status == IdentifierStatus.HALLUCINATED


async def test_verify_identifiers_version_present_in_evidence() -> None:
    verdict = _verdict(reasoning="Running version 5.7.31 per banner [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "port_banner", "summary": "5.7.31-MySQL", "content": ""}]
    )
    results = await verify_identifiers(verdict, bundle)
    version_result = next(r for r in results if r.kind == IdentifierKind.VERSION)
    assert version_result.status == IdentifierStatus.VERIFIED


async def test_verify_identifiers_version_absent_is_mismatch() -> None:
    verdict = _verdict(reasoning="Running version 9.9.9 per banner [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "port_banner", "summary": "5.7.31-MySQL", "content": ""}]
    )
    results = await verify_identifiers(verdict, bundle)
    version_result = next(r for r in results if r.kind == IdentifierKind.VERSION)
    assert version_result.status == IdentifierStatus.MISMATCH


async def test_verify_identifiers_hostname_matches_asset_value() -> None:
    verdict = _verdict(reasoning="Host db.example.com is exposed [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "dns_record", "summary": "", "content": ""}],
        asset_value="db.example.com",
    )
    results = await verify_identifiers(verdict, bundle)
    hostname_result = next(r for r in results if r.kind == IdentifierKind.HOSTNAME)
    assert hostname_result.status == IdentifierStatus.VERIFIED


async def test_verify_identifiers_hostname_not_in_graph_is_hallucinated() -> None:
    verdict = _verdict(reasoning="Host evil.attacker.com is exposed [ev_1].")
    bundle = _bundle(
        [{"id": "ev_1", "kind": "dns_record", "summary": "", "content": ""}],
        asset_value="db.example.com",
    )
    results = await verify_identifiers(verdict, bundle)
    hostname_result = next(r for r in results if r.kind == IdentifierKind.HOSTNAME)
    assert hostname_result.status == IdentifierStatus.HALLUCINATED


async def test_verify_identifiers_no_claims_returns_empty() -> None:
    verdict = _verdict(reasoning="Straightforward finding, nothing special here.")
    bundle = _bundle([{"id": "ev_1", "kind": "http_response", "summary": "", "content": ""}])
    results = await verify_identifiers(verdict, bundle)
    assert results == []
