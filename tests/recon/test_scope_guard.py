from __future__ import annotations

from kiyooo.db.models import ScopeAction, ScopeDecision, SeedKind
from kiyooo.db.repo.audit_log import AuditLogRepository
from kiyooo.recon.scope import OrgScopeOverlay, ScopeGuard, build_org_scope_overlay
from tests.recon.factories import make_exclusion, make_scope, make_seed


def _guard(
    audit_log_repo: AuditLogRepository,
    *,
    cli_active_flag: bool = False,
    org_overlay: OrgScopeOverlay | None = None,
    org_active_scanning_allowed: bool | None = None,
    **scope_overrides: object,
) -> ScopeGuard:
    return ScopeGuard(
        make_scope(**scope_overrides),
        cli_active_flag=cli_active_flag,
        audit_log_repo=audit_log_repo,
        scan_run_id=None,
        org_overlay=org_overlay,
        org_active_scanning_allowed=org_active_scanning_allowed,
    )


async def test_allow_exact_domain_passive(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo)
    result = await guard.check("example.com", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.ALLOW
    assert result.sendable


async def test_allow_wildcard_subdomain_passive(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo)
    result = await guard.check("api.example.com", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.ALLOW


async def test_domain_not_covered_by_wildcards_alone_is_denied(
    audit_log_repo: AuditLogRepository,
) -> None:
    """`domains` and `wildcards` are deliberately non-overlapping: a bare
    domain not also listed in `domains` isn't ALLOWed just because a wildcard
    covers its subdomains.
    """
    guard = _guard(audit_log_repo, domains=[], wildcards=["*.example.com"])
    result = await guard.check("example.com", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.DENY


async def test_allow_cidr_ip_passive(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo)
    result = await guard.check("203.0.113.42", tool="dnsx", is_active=False)
    assert result.decision == ScopeDecision.ALLOW


async def test_deny_out_of_scope_domain(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo)
    result = await guard.check("not-mine.example.org", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.DENY
    assert not result.sendable


async def test_deny_out_of_scope_ip(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo)
    result = await guard.check("198.51.100.7", tool="dnsx", is_active=False)
    assert result.decision == ScopeDecision.DENY


async def test_exclude_wins_even_when_domain_matches(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo, domains=["excluded.example.com"])
    result = await guard.check("excluded.example.com", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.DENY
    assert "exclude" in result.reason


async def test_exclude_wins_for_cidr_ip(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo, cli_active_flag=True, exclude=["203.0.113.0/28"])
    result = await guard.check("203.0.113.5", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.DENY
    assert "exclude" in result.reason


async def test_deny_active_without_config_enabled(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=False,
        attestation=False,
    )
    result = await guard.check("example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.DENY
    assert "authoriz" in result.reason.lower()


async def test_deny_active_without_cli_flag(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(
        audit_log_repo,
        cli_active_flag=False,
        active_scanning_enabled=True,
        attestation=True,
    )
    result = await guard.check("example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.DENY


async def test_allow_active_when_fully_authorized(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=True,
        attestation=True,
    )
    result = await guard.check("example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.ALLOW


async def test_requires_confirm_for_active_cidr_only_match(
    audit_log_repo: AuditLogRepository,
) -> None:
    """A target that matches only via `cidrs` (not an explicit domain or cloud
    account) needs REQUIRES_CONFIRM for active checks — IP ranges often cover
    shared/third-party infra you don't fully own.
    """
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=True,
        attestation=True,
        domains=[],
        wildcards=[],
        cloud_accounts=[],
    )
    result = await guard.check("203.0.113.42", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.REQUIRES_CONFIRM
    assert not result.sendable


async def test_requires_confirm_for_active_asn_only_match(
    audit_log_repo: AuditLogRepository,
) -> None:
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=True,
        attestation=True,
        domains=[],
        wildcards=[],
        cidrs=[],
        cloud_accounts=[],
    )
    result = await guard.check("AS64500", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.REQUIRES_CONFIRM


async def test_cidr_match_plus_domain_match_is_a_clean_allow(
    audit_log_repo: AuditLogRepository,
) -> None:
    """The REQUIRES_CONFIRM rule only fires when the match is *exclusively*
    range-based — an explicit domain match is enough to clear it even if the
    resolved IP also happens to fall in a configured CIDR.
    """
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=True,
        attestation=True,
        domains=["example.com"],
    )
    result = await guard.check("example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.ALLOW


async def test_passive_check_never_requires_confirm(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo, domains=[], wildcards=[], cloud_accounts=[])
    result = await guard.check("203.0.113.42", tool="dnsx", is_active=False)
    assert result.decision == ScopeDecision.ALLOW


async def test_every_check_writes_an_audit_log_row(audit_log_repo: AuditLogRepository) -> None:
    guard = _guard(audit_log_repo)
    await guard.check("example.com", tool="subfinder", is_active=False)
    await guard.check("not-mine.example.org", tool="subfinder", is_active=False)

    rows = await audit_log_repo.list_all()
    assert len(rows) == 2
    assert {row.target for row in rows} == {"example.com", "not-mine.example.org"}
    assert {row.decision for row in rows} == {ScopeDecision.ALLOW, ScopeDecision.DENY}


# --------------------------------------------------------------------------- #
# `--org` merge (kiyooo-easm-standalone.md Part D §1, build item 1). No
# `org_overlay` given at all (every test above this line) must stay
# byte-for-byte today's scope.yaml-only behavior — that's the backward-
# compat guarantee the "merge, don't replace" design promised.
# --------------------------------------------------------------------------- #


async def test_no_org_overlay_is_unaffected_by_what_a_db_seed_would_have_allowed(
    audit_log_repo: AuditLogRepository,
) -> None:
    """A target only a seed (never scope.yaml) would cover stays DENY when
    no `--org` was given — the DB never leaks into a plain `kiyooo scan`.
    """
    guard = _guard(audit_log_repo, domains=[], wildcards=[], cidrs=[], asns=[], cloud_accounts=[])
    result = await guard.check("seed-only.example.net", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.DENY


async def test_org_seed_domain_allows_a_target_scope_yaml_alone_would_deny(
    audit_log_repo: AuditLogRepository,
) -> None:
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="seed-only.example.net")], []
    )
    guard = _guard(
        audit_log_repo,
        org_overlay=overlay,
        domains=[],
        wildcards=[],
        cidrs=[],
        asns=[],
        cloud_accounts=[],
    )
    result = await guard.check("seed-only.example.net", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.ALLOW


async def test_org_seed_wildcard_cidr_asn_cloud_account_all_allow(
    audit_log_repo: AuditLogRepository,
) -> None:
    overlay = build_org_scope_overlay(
        [
            make_seed(kind=SeedKind.WILDCARD, value="*.seed.example.net"),
            make_seed(kind=SeedKind.CIDR, value="198.51.100.0/24"),
            make_seed(kind=SeedKind.ASN, value="AS64500"),
            make_seed(kind=SeedKind.CLOUD_ACCOUNT, value="seed-account"),
        ],
        [],
    )
    guard = _guard(
        audit_log_repo,
        org_overlay=overlay,
        domains=[],
        wildcards=[],
        cidrs=[],
        asns=[],
        cloud_accounts=[],
    )
    assert (
        await guard.check("api.seed.example.net", tool="t", is_active=False)
    ).decision == ScopeDecision.ALLOW
    assert (
        await guard.check("198.51.100.7", tool="t", is_active=False)
    ).decision == ScopeDecision.ALLOW
    assert (await guard.check("AS64500", tool="t", is_active=False)).decision == ScopeDecision.ALLOW
    assert (
        await guard.check("seed-account-bucket", tool="t", is_active=False)
    ).decision == ScopeDecision.ALLOW


async def test_org_level_exclusion_beats_a_scope_yaml_include(
    audit_log_repo: AuditLogRepository,
) -> None:
    """Exclusion beats include in every case — including when the include
    comes from scope.yaml and the exclusion comes from the DB.
    """
    overlay = build_org_scope_overlay([], [make_exclusion(value="excluded-by-org.example.com")])
    guard = _guard(audit_log_repo, org_overlay=overlay, domains=["excluded-by-org.example.com"])
    result = await guard.check("excluded-by-org.example.com", tool="t", is_active=False)
    assert result.decision == ScopeDecision.DENY
    assert "exclude" in result.reason


async def test_global_exclusion_beats_an_org_seed_include(
    audit_log_repo: AuditLogRepository,
) -> None:
    """A global exclusion (`org_id=None`) applies on top of an org's own
    seeds — it's the caller's job (`ExclusionRepository.
    list_for_org_and_global`) to have already merged the two lists before
    calling `build_org_scope_overlay`; this asserts the overlay/ScopeGuard
    side honors that once it's merged in.
    """
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="globally-excluded.example.com")],
        [make_exclusion(org_id=None, value="globally-excluded.example.com")],
    )
    guard = _guard(
        audit_log_repo,
        org_overlay=overlay,
        domains=[],
        wildcards=[],
        cidrs=[],
        asns=[],
        cloud_accounts=[],
    )
    result = await guard.check("globally-excluded.example.com", tool="t", is_active=False)
    assert result.decision == ScopeDecision.DENY


async def test_seeds_own_exclude_scope_action_beats_a_scope_yaml_include(
    audit_log_repo: AuditLogRepository,
) -> None:
    """A seed can itself be an exclude entry (`scope_action=exclude`), not
    only the separate `exclusion` table — this beats scope.yaml's include
    the same way.
    """
    overlay = build_org_scope_overlay(
        [
            make_seed(
                kind=SeedKind.APEX_DOMAIN,
                value="carved-out.example.com",
                scope_action=ScopeAction.EXCLUDE,
            )
        ],
        [],
    )
    guard = _guard(audit_log_repo, org_overlay=overlay, domains=["carved-out.example.com"])
    result = await guard.check("carved-out.example.com", tool="t", is_active=False)
    assert result.decision == ScopeDecision.DENY


# --------------------------------------------------------------------------- #
# Regression: `organization.active_scanning_allowed` (forced False for
# relationship=third_party — OrganizationRepository.create) is a real
# invariant #2/#3 gate now, checked here at ScopeGuard itself, not only at
# org-creation time. Found by code review: the overlay let a third-party
# org's seeds resolve targets, but nothing stopped an ACTIVE scan of them.
# --------------------------------------------------------------------------- #


async def test_org_active_scanning_allowed_false_denies_even_when_scope_yaml_authorizes(
    audit_log_repo: AuditLogRepository,
) -> None:
    """The exact bug: an operator's own scope.yaml is fully authorized for
    active scanning (this is normal — they use it for their own org), but
    the org passed via `--org` is third_party (`active_scanning_allowed=
    False`, structurally, at creation). That must still deny an active
    check against that org's own seeded target.
    """
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="vendor.example.com")], []
    )
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=True,
        attestation=True,
        domains=[],
        org_overlay=overlay,
        org_active_scanning_allowed=False,
    )
    result = await guard.check("vendor.example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.DENY
    assert "third_party" in result.reason or "active_scanning_allowed" in result.reason


async def test_org_active_scanning_allowed_false_still_allows_passive(
    audit_log_repo: AuditLogRepository,
) -> None:
    """The org-level gate only applies to active checks — a third-party
    org's seeds are still legitimately usable for passive recon.
    """
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="vendor.example.com")], []
    )
    guard = _guard(
        audit_log_repo, domains=[], org_overlay=overlay, org_active_scanning_allowed=False
    )
    result = await guard.check("vendor.example.com", tool="subfinder", is_active=False)
    assert result.decision == ScopeDecision.ALLOW


async def test_org_active_scanning_allowed_true_still_needs_scope_yamls_own_gates(
    audit_log_repo: AuditLogRepository,
) -> None:
    """The org's gate is additional, never a substitute — even a fully-
    permitted org (active_scanning_allowed=True) can't actively scan if
    the operator's own scope.yaml isn't itself authorized.
    """
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="acme.example.com")], []
    )
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=False,
        attestation=True,
        domains=[],
        org_overlay=overlay,
        org_active_scanning_allowed=True,
    )
    result = await guard.check("acme.example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.DENY


async def test_org_active_scanning_allowed_true_and_scope_yaml_authorized_allows(
    audit_log_repo: AuditLogRepository,
) -> None:
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="acme.example.com")], []
    )
    guard = _guard(
        audit_log_repo,
        cli_active_flag=True,
        active_scanning_enabled=True,
        attestation=True,
        domains=[],
        org_overlay=overlay,
        org_active_scanning_allowed=True,
    )
    result = await guard.check("acme.example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.ALLOW


async def test_no_org_given_active_scanning_unaffected_by_org_gate(
    audit_log_repo: AuditLogRepository,
) -> None:
    """`org_active_scanning_allowed=None` (no `--org`) must not add any
    extra requirement — the backward-compat guarantee, for the active-scan
    gate specifically.
    """
    guard = _guard(
        audit_log_repo, cli_active_flag=True, active_scanning_enabled=True, attestation=True
    )
    result = await guard.check("example.com", tool="naabu", is_active=True)
    assert result.decision == ScopeDecision.ALLOW
