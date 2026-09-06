"""ScopeGuard — the hard boundary.

Every adapter calls `ScopeGuard.check()` before it sends a single packet to a
target. No other code path is permitted to originate outbound network activity
against a target. This is enforced by convention at this layer (there is no
sandboxing that physically prevents an adapter from ignoring it) — the discipline
is: `run()` implementations call `check()` first and branch on the result, full
stop. `orchestrator.py` never calls a tool for a target ScopeGuard has not ALLOWed.

**Matching rules (Stage 1 interpretation — the design doc gives the config fields but
not their exact matching semantics):**

- `domains`: exact hostname match only. A domain you own also needs its
  subdomains listed in `wildcards` — the two lists are intentionally not
  overlapping, so `scope.yaml` says what it means.
- `wildcards`: glob match (`*.acmecorp.example` via `fnmatch`) against the
  hostname.
- `cidrs`: IP containment via `ipaddress`.
- `asns`: literal match only, against a target already given in `AS<number>`
  form. Resolving an arbitrary IP to its ASN is an enrichment lookup (the design doc
  §6 `enrich/asn.py`, Stage 3), not something ScopeGuard does itself — doing
  live ASN resolution inside the scope check would make the safety boundary
  depend on a third-party lookup succeeding.
- `cloud_accounts`: substring match against the target string. Precise
  resource-level cloud scoping is Stage 3's job (`enrich/cloud_*.py` tags the
  owning account onto the asset); this is a conservative stand-in until that
  exists.
- `exclude`: same matching rules as above (hostname/wildcard/CIDR), checked
  first, and wins over every inclusion rule unconditionally.

**Why `REQUIRES_CONFIRM` exists:** a target that only matches via `cidrs` or
`asns` — an IP range, not a named domain or cloud account — often covers
shared hosting or cloud-provider infrastructure that includes neighbors you
don't actually own. For active (packet-sending) checks, a range-only match
returns `REQUIRES_CONFIRM` rather than `ALLOW`: Stage 1 has no interactive
confirmation flow yet, so the orchestrator treats it the same as `DENY` for
now (skips the target) but logs and reports it distinctly, because the fix is
different — add the exact domain to `scope.yaml`, don't just re-run. Passive
checks and exact domain/wildcard/cloud-account matches never require confirm.
"""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

import structlog

from kiyooo.config import ScopeConfig
from kiyooo.db.models import AuditLog, Exclusion, ScopeDecision, Seed, SeedKind
from kiyooo.db.repo.audit_log import AuditLogRepository

_logger = structlog.get_logger()

# Seed/exclusion kinds `build_org_scope_overlay` can translate into one of
# ScopeGuard's existing match buckets (domains/wildcards/cidrs/asns/
# cloud_accounts). GITHUB_ORG/SAAS_TENANT/BRAND_TERM identify no network
# target — kiyooo-easm-standalone.md Part D §2's expansion step is what
# would turn one of those into checkable hosts, and that's not built yet.
_UNENFORCEABLE_KINDS = frozenset({SeedKind.GITHUB_ORG, SeedKind.SAAS_TENANT, SeedKind.BRAND_TERM})


@dataclass(frozen=True, slots=True)
class ScopeCheckResult:
    decision: ScopeDecision
    reason: str

    @property
    def sendable(self) -> bool:
        """True only for a clean ALLOW. DENY and REQUIRES_CONFIRM both mean: no
        packet goes out from this check, whatever the reason.
        """
        return self.decision == ScopeDecision.ALLOW


def _extract_host(target: str) -> str:
    if "://" in target:
        host = urlsplit(target).hostname
        return host or target
    # host:port form, e.g. from a tcp_service asset value
    if ":" in target and not target.count(":") > 1:  # not IPv6
        host, _, rest = target.partition(":")
        if rest.isdigit():
            return host
    return target


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _matches_hostname_rules(host: str, domains: list[str], wildcards: list[str]) -> bool:
    if host in domains:
        return True
    return any(fnmatch.fnmatch(host, pattern) for pattern in wildcards)


def _matches_exclude_hostname(host: str, exclude: list[str]) -> bool:
    """`exclude` entries can be an exact hostname or a glob, so check both ways
    against the one list rather than requiring the author to know which.
    """
    return host in exclude or any(fnmatch.fnmatch(host, pattern) for pattern in exclude)


def _matches_cidr(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, cidrs: list[str]) -> bool:
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip in network:
            return True
    return False


def _matches_asn(target: str, asns: list[int]) -> bool:
    stripped = target.upper().removeprefix("AS")
    if not stripped.isdigit():
        return False
    return int(stripped) in asns


def _matches_cloud_account(target: str, cloud_accounts: list[str]) -> bool:
    return any(account and account in target for account in cloud_accounts)


@dataclass(frozen=True, slots=True)
class OrgScopeOverlay:
    """The DB-backed equivalent of `ScopeConfig`'s scope.yaml lists, for one
    org — built by `build_org_scope_overlay` from that org's `Seed`/
    `Exclusion` rows. `ScopeGuard._decide` checks the union of a
    `ScopeConfig` and (when `--org` was given) one of these; the matching
    logic itself never changes, only how long the lists it checks are.
    """

    domains: list[str] = field(default_factory=list)
    wildcards: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    asns: list[int] = field(default_factory=list)
    cloud_accounts: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


def build_org_scope_overlay(seeds: list[Seed], exclusions: list[Exclusion]) -> OrgScopeOverlay:
    """Folds one org's `Seed`/`Exclusion` rows into `ScopeGuard`'s existing
    match buckets. `seeds` should already be the caller's *enabled* seeds
    (`SeedRepository.list_for_org`'s default excludes disabled ones) —
    this function has no opinion on `disabled_at`, it just reads `kind`/
    `value`/`scope_action` off whatever it's given.

    GITHUB_ORG/SAAS_TENANT/BRAND_TERM seeds, and ASN/cloud-account-kind
    exclusions, are silently skipped here — not an oversight, see
    `_UNENFORCEABLE_KINDS` and `Exclusion`'s docstring for why.
    """
    domains: list[str] = []
    wildcards: list[str] = []
    cidrs: list[str] = []
    asns: list[int] = []
    cloud_accounts: list[str] = []
    exclude: list[str] = []

    for seed in seeds:
        if seed.kind in _UNENFORCEABLE_KINDS:
            continue
        excluding = seed.scope_action.value == "exclude"
        if seed.kind in (SeedKind.APEX_DOMAIN, SeedKind.SUBDOMAIN, SeedKind.EMAIL_DOMAIN):
            (exclude if excluding else domains).append(seed.value)
        elif seed.kind == SeedKind.WILDCARD:
            (exclude if excluding else wildcards).append(seed.value)
        elif seed.kind == SeedKind.URL:
            (exclude if excluding else domains).append(_extract_host(seed.value))
        elif seed.kind == SeedKind.IP:
            (exclude if excluding else cidrs).append(f"{seed.value}/32")
        elif seed.kind == SeedKind.CIDR:
            (exclude if excluding else cidrs).append(seed.value)
        elif seed.kind == SeedKind.ASN:
            stripped = seed.value.upper().removeprefix("AS")
            if stripped.isdigit() and not excluding:
                asns.append(int(stripped))
            # An excluded ASN seed has nowhere to go: ScopeGuard's exclude
            # check is hostname/CIDR-shaped only. Stored, not enforced.
        elif seed.kind == SeedKind.CLOUD_ACCOUNT:
            (exclude if excluding else cloud_accounts).append(seed.value)

    for excl in exclusions:
        if excl.kind in (
            SeedKind.APEX_DOMAIN,
            SeedKind.SUBDOMAIN,
            SeedKind.EMAIL_DOMAIN,
            SeedKind.WILDCARD,
        ):
            exclude.append(excl.value)
        elif excl.kind == SeedKind.URL:
            exclude.append(_extract_host(excl.value))
        elif excl.kind == SeedKind.IP:
            exclude.append(f"{excl.value}/32")
        elif excl.kind == SeedKind.CIDR:
            exclude.append(excl.value)
        # ASN/CLOUD_ACCOUNT/unenforceable-kind exclusions: stored, not
        # enforced — same limit noted on `Exclusion` and above.

    return OrgScopeOverlay(
        domains=domains,
        wildcards=wildcards,
        cidrs=cidrs,
        asns=asns,
        cloud_accounts=cloud_accounts,
        exclude=exclude,
    )


class ScopeGuard:
    """One instance per scan run, shared by every adapter running in it. Holds
    the parsed `scope.yaml` plus the process-wide `--active` CLI flag, and
    writes an `audit_log` row for every decision it makes.

    The orchestrator runs multiple adapters concurrently within a stage, and
    they all call `check()` on this same instance — but `AuditLogRepository`
    wraps one `AsyncSession`, and `AsyncSession` is not safe for concurrent
    use from more than one coroutine at a time. `_lock` serializes the
    decide-and-audit-write around `check()` so concurrent adapters never touch
    the session at the same instant; it does not serialize the adapters'
    actual `run()` calls, which is where the real time is spent.
    """

    def __init__(
        self,
        scope: ScopeConfig,
        *,
        cli_active_flag: bool,
        audit_log_repo: AuditLogRepository,
        scan_run_id: UUID | None,
        org_overlay: OrgScopeOverlay | None = None,
        org_active_scanning_allowed: bool | None = None,
    ) -> None:
        self._scope = scope
        self._cli_active_flag = cli_active_flag
        self._audit_log_repo = audit_log_repo
        self._scan_run_id = scan_run_id
        self._lock = asyncio.Lock()
        self._org_overlay = org_overlay
        # None = no `--org` given, this gate doesn't apply (pure scope.yaml
        # behavior, unchanged). Not-None = the org's own
        # `active_scanning_allowed` (forced False at creation for
        # relationship=third_party — see OrganizationRepository.create) is
        # an ADDITIONAL requirement, checked here at the actual outbound-
        # packet gate per CLAUDE.md invariant #2, not only at the point an
        # org row gets created.
        self._org_active_scanning_allowed = org_active_scanning_allowed
        # Merged once here, not recomputed per `check()` call — a scan run
        # can call `check()` thousands of times. `org_overlay=None` (no
        # `--org` given) makes every one of these identical to `scope.X`,
        # so a scan run with no org is byte-for-byte today's behavior.
        overlay = org_overlay or OrgScopeOverlay()
        self._domains = scope.domains + overlay.domains
        self._wildcards = scope.wildcards + overlay.wildcards
        self._cidrs = scope.cidrs + overlay.cidrs
        self._asns = scope.asns + overlay.asns
        self._cloud_accounts = scope.cloud_accounts + overlay.cloud_accounts
        self._exclude = scope.exclude + overlay.exclude

    async def check(
        self, target: str, *, tool: str, is_active: bool, finding_id: UUID | None = None
    ) -> ScopeCheckResult:
        result = self._decide(target, is_active=is_active)
        async with self._lock:
            await self._audit(
                target, tool=tool, is_active=is_active, result=result, finding_id=finding_id
            )
        if result.decision == ScopeDecision.DENY:
            _logger.warning("scope_guard.deny", target=target, tool=tool, reason=result.reason)
        return result

    def _decide(self, target: str, *, is_active: bool) -> ScopeCheckResult:
        host = _extract_host(target)
        ip = _as_ip(host)

        exclude_reason = "excluded by the configured exclude list (scope.yaml" + (
            " and/or org exclusions)" if self._org_overlay is not None else ")"
        )
        if _matches_exclude_hostname(host, self._exclude):
            return ScopeCheckResult(ScopeDecision.DENY, exclude_reason)
        if ip is not None and _matches_cidr(ip, self._exclude):
            return ScopeCheckResult(ScopeDecision.DENY, exclude_reason)

        matched_domain = _matches_hostname_rules(host, self._domains, self._wildcards)
        matched_cidr = ip is not None and _matches_cidr(ip, self._cidrs)
        matched_asn = _matches_asn(target, self._asns)
        matched_cloud = _matches_cloud_account(target, self._cloud_accounts)

        if not (matched_domain or matched_cidr or matched_asn or matched_cloud):
            source = "scope.yaml or org seeds" if self._org_overlay is not None else "scope.yaml"
            return ScopeCheckResult(
                ScopeDecision.DENY,
                f"target not covered by any domain/wildcard/cidr/asn/cloud_account in {source}",
            )

        if not is_active:
            return ScopeCheckResult(ScopeDecision.ALLOW, "passive lookup, target in scope")

        if not self._active_scanning_authorized():
            reason = (
                "active scanning not authorized: requires active_scanning_enabled in "
                "scope.yaml, --active on the CLI, and attestation: true"
            )
            if self._org_active_scanning_allowed is False:
                reason += (
                    "; this org's active_scanning_allowed is false (third_party orgs "
                    "are always passive-only, not overridable)"
                )
            return ScopeCheckResult(ScopeDecision.DENY, reason)

        range_only_match = (matched_cidr or matched_asn) and not (matched_domain or matched_cloud)
        if range_only_match:
            return ScopeCheckResult(
                ScopeDecision.REQUIRES_CONFIRM,
                "target matched only via an IP range/ASN, not an explicit domain or cloud "
                "account — add the exact host to scope.yaml to allow an active scan",
            )

        return ScopeCheckResult(ScopeDecision.ALLOW, "active scan authorized, target in scope")

    def _active_scanning_authorized(self) -> bool:
        base = (
            self._scope.active_scanning_enabled
            and self._cli_active_flag
            and self._scope.attestation
        )
        if self._org_active_scanning_allowed is None:
            return base
        # `--org` was given: the org's own gate is an ADDITIONAL
        # requirement on top of scope.yaml's, never a substitute for it —
        # this can only narrow authorization, never widen it.
        return base and self._org_active_scanning_allowed

    async def _audit(
        self,
        target: str,
        *,
        tool: str,
        is_active: bool,
        result: ScopeCheckResult,
        finding_id: UUID | None,
    ) -> None:
        await self._audit_log_repo.add(
            AuditLog(
                scan_run_id=self._scan_run_id,
                finding_id=finding_id,
                tool=tool,
                target=target,
                is_active=is_active,
                decision=result.decision,
                reason=result.reason,
                occurred_at=datetime.now(UTC),
            )
        )
