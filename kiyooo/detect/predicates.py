"""The predicate library used by category and control YAML (the design
Stage 4). Every predicate is pure — `(asset, evidence, ctx, arg) ->
PredicateResult` — and records which `Evidence` row(s) it matched, since
that's what feeds citations in Stage 5's LLM bundle.

17 predicates ship here (plus `evidence_injection_suspected` for Stage
11b's `mcp-tool-poisoning-risk`, and `tls_protocol_version_in`/
`nuclei_tags_include` for Stage 12's `weak-tls-version`/`generic-web-cve`
demo-lab categories), 3 more than the design's prose list of 13 in §7 — each
one is still plan-sourced, just missing from that summary paragraph:
`tls_cert_expires_within_days` because `expired-cert.yaml` (a required core
category, and the DoD's own clustering demo case) has no other way to
detect an expiring certificate; `tls_handshake_requires_client_cert`
because it's `mtls_required`'s own `detect:` clause in the design's
worked controls.yaml example; `service_banner_matches` because
`exposed-database.yaml`'s worked example (also already shipped in
org-context.example) pairs it with `port_in` as a fingerprint check that a
port really is the claimed database service, not just an open port.

Some predicates read an evidence-content field no adapter populates yet
(`http_header_matches`'s `header` dict, `http_body_matches`/
`body_entropy_above`'s `body` string, `resolved_ip_in_asn`'s `ASN_RECORD`
evidence, `cloud_tag_equals`'s `CLOUD_CONFIG` evidence,
`service_banner_matches`'s `banner` string, `tls_handshake_requires_
client_cert`'s `requires_client_cert` bool). Each is still pure and
fixture-tested — the same "real logic now, live data once a producer
exists" treatment already given to `enrich/kev.py`/`enrich/epss.py` and the
GCP/Azure enrichment stubs in Stage 3.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from kiyooo.db.models import Asset, AssetType, Control, Evidence, EvidenceKind
from kiyooo.enrich.epss import EpssScore
from kiyooo.enrich.kev import KevCatalog

_LOGIN_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "sign in",
    "log in",
    "authentication required",
)


@dataclass(frozen=True, slots=True)
class PredicateContext:
    kev_catalog: KevCatalog | None = None
    epss_scores: dict[str, EpssScore] = field(default_factory=dict)
    detected_controls: list[Control] = field(default_factory=list)
    now: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class PredicateResult:
    matched: bool
    evidence_ids: list[str] = field(default_factory=list)
    # Category-specific fingerprint component (CVE id, cert serial, ...) —
    # see `normalize/fingerprint.py`. None for predicates that don't
    # distinguish between different instances of the same issue.
    discriminator: str | None = None


_NO_MATCH = PredicateResult(matched=False)


def _of_kind(evidence: list[Evidence], kind: EvidenceKind) -> list[Evidence]:
    return [item for item in evidence if item.kind == kind]


def _hostname_of(asset: Asset) -> str:
    if asset.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return asset.value
    if asset.type in (AssetType.HTTP_SERVICE, AssetType.URL):
        return urlsplit(asset.value).hostname or ""
    if asset.type in (AssetType.TCP_SERVICE, AssetType.CERT):
        return asset.value.split(":", 1)[0]
    return asset.value


def _requires_auth(record: dict[str, object]) -> bool:
    """Same heuristic as `graph/snapshot.py`'s `_build_state` — a status
    code of 401/403, or a login-page keyword in the title.
    """
    status_code = record.get("status_code")
    title = str(record.get("title") or "")
    return status_code in (401, 403) or any(keyword in title.lower() for keyword in _LOGIN_KEYWORDS)


def cve_ids_from_nuclei_record(record: dict[str, object]) -> list[str]:
    """Public — `cli.py`'s `detect run` also uses this to know which CVE ids
    a scan actually found, so it only fetches EPSS scores for those.
    """
    info = record.get("info")
    if not isinstance(info, dict):
        return []
    classification = info.get("classification")
    if not isinstance(classification, dict):
        return []
    cve_ids = classification.get("cve-id")
    if not isinstance(cve_ids, list):
        return []
    return [str(c).upper() for c in cve_ids]


# --------------------------------------------------------------------------- #
# hostname / header / body / redirect-chain matching
# --------------------------------------------------------------------------- #


def hostname_matches(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    pattern = re.compile(str(arg), re.IGNORECASE)
    hostname = _hostname_of(asset)
    if hostname and pattern.search(hostname):
        return PredicateResult(matched=True)
    return _NO_MATCH


def http_header_matches(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """`arg` is `{header_name: pattern}`. Reads
    `Evidence.content_inline["header"]` as a `dict[str, str]` — the contract
    a future `-include-response-header` httpx flag would populate.
    """
    if not isinstance(arg, dict):
        return _NO_MATCH
    for item in _of_kind(evidence, EvidenceKind.HTTP_RESPONSE):
        record = item.content_inline or {}
        headers = record.get("header")
        if not isinstance(headers, dict):
            continue
        for header_name, pattern in arg.items():
            value = headers.get(header_name)
            if value is not None and re.search(str(pattern), str(value), re.IGNORECASE):
                return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def http_body_matches(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """Reads `Evidence.content_inline["body"]` — the contract a future
    `-include-response` httpx flag would populate.
    """
    pattern = re.compile(str(arg), re.IGNORECASE | re.DOTALL)
    for item in _of_kind(evidence, EvidenceKind.HTTP_RESPONSE):
        record = item.content_inline or {}
        body = record.get("body")
        if isinstance(body, str) and pattern.search(body):
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def redirect_chain_matches(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """Reads `Evidence.content_inline["chain"]` — a list of hop URLs, the
    shape httpx's `-follow-redirects -json` produces under a `chain` key.
    """
    pattern = re.compile(str(arg), re.IGNORECASE)
    for item in _of_kind(evidence, EvidenceKind.HTTP_RESPONSE):
        record = item.content_inline or {}
        chain = record.get("chain")
        if not isinstance(chain, list):
            continue
        for hop in chain:
            if pattern.search(str(hop)):
                return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def body_entropy_above(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """Shannon entropy of the HTTP response body — a high-entropy substring
    embedded in an otherwise ordinary page is the classic signature of a
    leaked API key or token. Reads the same `body` field as
    `http_body_matches`.
    """
    threshold = float(arg)  # type: ignore[arg-type]
    for item in _of_kind(evidence, EvidenceKind.HTTP_RESPONSE):
        record = item.content_inline or {}
        body = record.get("body")
        if isinstance(body, str) and body and _shannon_entropy(body) > threshold:
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


# --------------------------------------------------------------------------- #
# port / reachability / auth
# --------------------------------------------------------------------------- #


def port_in(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    if not isinstance(arg, list):
        return _NO_MATCH
    ports = {int(p) for p in arg}
    for item in _of_kind(evidence, EvidenceKind.PORT_BANNER):
        record = item.content_inline or {}
        port = record.get("port")
        if isinstance(port, int) and port in ports:
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def service_banner_matches(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """Confirms a port is actually the claimed service, not just open on
    that number. Reads `Evidence.content_inline["banner"]` — the contract a
    future banner-grabbing capability (naabu has none; a dedicated adapter
    would) would populate.
    """
    pattern = re.compile(str(arg), re.IGNORECASE)
    for item in _of_kind(evidence, EvidenceKind.PORT_BANNER):
        record = item.content_inline or {}
        banner = record.get("banner")
        if isinstance(banner, str) and pattern.search(banner):
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def internet_reachable(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """An asset was actually probed and answered this scan — at least one
    `HTTP_RESPONSE` or `PORT_BANNER` evidence item exists for it.
    """
    reachable_evidence = _of_kind(evidence, EvidenceKind.HTTP_RESPONSE) + _of_kind(
        evidence, EvidenceKind.PORT_BANNER
    )
    matched = bool(reachable_evidence) == bool(arg)
    if matched:
        return PredicateResult(matched=True, evidence_ids=[e.id for e in reachable_evidence])
    return _NO_MATCH


def responds_without_auth(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    for item in _of_kind(evidence, EvidenceKind.HTTP_RESPONSE):
        record = item.content_inline or {}
        without_auth = not _requires_auth(record)
        if without_auth == bool(arg):
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


# --------------------------------------------------------------------------- #
# TLS certificate
# --------------------------------------------------------------------------- #


def tls_cert_cn_matches(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    pattern = re.compile(str(arg), re.IGNORECASE)
    for item in _of_kind(evidence, EvidenceKind.TLS_CERT):
        record = item.content_inline or {}
        cn = record.get("subject_cn")
        if isinstance(cn, str) and pattern.search(cn):
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def tls_cert_expires_within_days(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    days = int(arg)  # type: ignore[call-overload]
    for item in _of_kind(evidence, EvidenceKind.TLS_CERT):
        record = item.content_inline or {}
        not_after = record.get("not_after")
        if not isinstance(not_after, str):
            continue
        try:
            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        except ValueError:
            continue
        if (expiry - ctx.now).days <= days:
            serial = record.get("serial_number")
            discriminator = str(serial) if serial else None
            return PredicateResult(
                matched=True, evidence_ids=[item.id], discriminator=discriminator
            )
    return _NO_MATCH


def tls_handshake_requires_client_cert(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """the design's `mtls_required` control detects exactly this. Reads
    `Evidence.content_inline["requires_client_cert"]` — the contract a
    future dedicated mTLS-enforcement probe would populate; `tlsx` doesn't
    test this passively (it would require attempting a handshake with no
    client cert and observing the rejection, an active differential
    probe — Stage 6 territory, not Stage 1's passive `tlsx` adapter).
    """
    for item in _of_kind(evidence, EvidenceKind.TLS_CERT):
        record = item.content_inline or {}
        requires_client_cert = record.get("requires_client_cert")
        if isinstance(requires_client_cert, bool) and requires_client_cert == bool(arg):
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def tls_protocol_version_in(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """Reads `Evidence.content_inline["protocol_version"]` — the contract
    a `tlsx`-shaped adapter populates from the handshake it already
    performs (tlsx reports the negotiated TLS version natively; no extra
    probe needed). Used by `weak-tls-version.yaml`.
    """
    if not isinstance(arg, list):
        return _NO_MATCH
    versions = {str(v) for v in arg}
    for item in _of_kind(evidence, EvidenceKind.TLS_CERT):
        record = item.content_inline or {}
        version = record.get("protocol_version")
        if isinstance(version, str) and version in versions:
            return PredicateResult(matched=True, evidence_ids=[item.id], discriminator=version)
    return _NO_MATCH


# --------------------------------------------------------------------------- #
# cloud / ASN — pure now, no producing adapter yet (see module docstring)
# --------------------------------------------------------------------------- #


def resolved_ip_in_asn(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    if not isinstance(arg, list):
        return _NO_MATCH
    asns = {int(a) for a in arg}
    for item in _of_kind(evidence, EvidenceKind.ASN_RECORD):
        record = item.content_inline or {}
        asn = record.get("asn")
        if isinstance(asn, int) and asn in asns:
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


def cloud_tag_equals(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    if not isinstance(arg, dict):
        return _NO_MATCH
    for item in _of_kind(evidence, EvidenceKind.CLOUD_CONFIG):
        record = item.content_inline or {}
        tags = record.get("tags")
        if not isinstance(tags, dict):
            continue
        if all(tags.get(key) == value for key, value in arg.items()):
            return PredicateResult(matched=True, evidence_ids=[item.id])
    return _NO_MATCH


# --------------------------------------------------------------------------- #
# compensating controls
# --------------------------------------------------------------------------- #


def has_control(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    for control in ctx.detected_controls:
        if control.asset_id == asset.id and control.control_id == str(arg):
            control_id = control.evidence_id
            return PredicateResult(matched=True, evidence_ids=[control_id] if control_id else [])
    return _NO_MATCH


def evidence_injection_suspected(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """Stage 11b's `mcp-tool-poisoning-risk`: a tool
    *description* enters a client's context window with instruction-level
    authority, so this points Stage 4.5's injection canary
    (`normalize/injection.py`, already run on every evidence write — see
    `recon/orchestrator.py`, `ingest/pipeline.py`, `verify/executor.py`)
    at the org's own AI tool inventory rather than building a second
    detector.
    """
    flagged = [item for item in evidence if item.injection_suspected]
    matched = bool(flagged) == bool(arg)
    if matched:
        return PredicateResult(matched=True, evidence_ids=[e.id for e in flagged])
    return _NO_MATCH


# --------------------------------------------------------------------------- #
# KEV / EPSS — reads CVE ids off nuclei's `info.classification.cve-id`
# --------------------------------------------------------------------------- #


def nuclei_tags_include(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    """Reads nuclei's own `info.tags[]` — a standard field on every nuclei
    template, not something a new adapter needs to add. Used by
    `generic-web-cve.yaml` to detect a signature-based (never exploit-based
    — Stage 1's `NucleiAdapter` already excludes `dos`/`intrusive`/`fuzz`
    tags) vulnerability-class hit, e.g. a `sqli`- or `xss`-tagged template.
    """
    if not isinstance(arg, list):
        return _NO_MATCH
    wanted = {str(t).lower() for t in arg}
    for item in _of_kind(evidence, EvidenceKind.NUCLEI_RESULT):
        record = item.content_inline or {}
        info = record.get("info")
        tags = info.get("tags") if isinstance(info, dict) else None
        if not isinstance(tags, list):
            continue
        present = {str(t).lower() for t in tags}
        overlap = wanted & present
        if overlap:
            return PredicateResult(
                matched=True, evidence_ids=[item.id], discriminator=sorted(overlap)[0]
            )
    return _NO_MATCH


def cve_in_kev(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    if ctx.kev_catalog is None:
        return _NO_MATCH
    for item in _of_kind(evidence, EvidenceKind.NUCLEI_RESULT):
        record = item.content_inline or {}
        for cve_id in cve_ids_from_nuclei_record(record):
            if ctx.kev_catalog.is_known_exploited(cve_id) == bool(arg):
                return PredicateResult(matched=True, evidence_ids=[item.id], discriminator=cve_id)
    return _NO_MATCH


def epss_above(
    asset: Asset, evidence: list[Evidence], ctx: PredicateContext, arg: object
) -> PredicateResult:
    threshold = float(arg)  # type: ignore[arg-type]
    for item in _of_kind(evidence, EvidenceKind.NUCLEI_RESULT):
        record = item.content_inline or {}
        for cve_id in cve_ids_from_nuclei_record(record):
            score = ctx.epss_scores.get(cve_id)
            if score is not None and score.score > threshold:
                return PredicateResult(matched=True, evidence_ids=[item.id], discriminator=cve_id)
    return _NO_MATCH


# --------------------------------------------------------------------------- #
# registry — the only thing `detect/engine.py` and `detect/controls.py`
# need to evaluate a predicate clause without a giant if/elif chain.
# --------------------------------------------------------------------------- #

PredicateFn = Callable[[Asset, list[Evidence], PredicateContext, object], PredicateResult]

PREDICATES: dict[str, PredicateFn] = {
    "hostname_matches": hostname_matches,
    "http_header_matches": http_header_matches,
    "http_body_matches": http_body_matches,
    "port_in": port_in,
    "service_banner_matches": service_banner_matches,
    "tls_cert_cn_matches": tls_cert_cn_matches,
    "tls_cert_expires_within_days": tls_cert_expires_within_days,
    "tls_handshake_requires_client_cert": tls_handshake_requires_client_cert,
    "internet_reachable": internet_reachable,
    "resolved_ip_in_asn": resolved_ip_in_asn,
    "cloud_tag_equals": cloud_tag_equals,
    "has_control": has_control,
    "cve_in_kev": cve_in_kev,
    "epss_above": epss_above,
    "responds_without_auth": responds_without_auth,
    "redirect_chain_matches": redirect_chain_matches,
    "body_entropy_above": body_entropy_above,
    "evidence_injection_suspected": evidence_injection_suspected,
    "tls_protocol_version_in": tls_protocol_version_in,
    "nuclei_tags_include": nuclei_tags_include,
}
