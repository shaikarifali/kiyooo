"""`build_org_scope_overlay` — the seed/exclusion-kind-to-ScopeGuard-bucket
mapping, tested in isolation from `ScopeGuard` itself (that integration is
`test_scope_guard.py`'s job). Pure function, plain objects in — no DB, no
`AsyncSession`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from kiyooo.db.models import ScopeAction, SeedKind
from kiyooo.recon.scope import build_org_scope_overlay
from tests.recon.factories import make_exclusion, make_seed


def test_apex_domain_seed_goes_to_domains() -> None:
    overlay = build_org_scope_overlay([make_seed(kind=SeedKind.APEX_DOMAIN, value="a.com")], [])
    assert overlay.domains == ["a.com"]
    assert overlay.wildcards == overlay.cidrs == overlay.asns == overlay.cloud_accounts == []


def test_subdomain_and_email_domain_seeds_also_go_to_domains() -> None:
    overlay = build_org_scope_overlay(
        [
            make_seed(kind=SeedKind.SUBDOMAIN, value="app.a.com"),
            make_seed(kind=SeedKind.EMAIL_DOMAIN, value="a.com"),
        ],
        [],
    )
    assert overlay.domains == ["app.a.com", "a.com"]


def test_wildcard_seed_goes_to_wildcards() -> None:
    overlay = build_org_scope_overlay([make_seed(kind=SeedKind.WILDCARD, value="*.a.com")], [])
    assert overlay.wildcards == ["*.a.com"]


def test_url_seed_is_reduced_to_its_host_in_domains() -> None:
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.URL, value="https://a.com/portal")], []
    )
    assert overlay.domains == ["a.com"]


def test_ip_seed_becomes_a_slash_32_cidr() -> None:
    overlay = build_org_scope_overlay([make_seed(kind=SeedKind.IP, value="203.0.113.42")], [])
    assert overlay.cidrs == ["203.0.113.42/32"]


def test_cidr_seed_passes_through() -> None:
    overlay = build_org_scope_overlay([make_seed(kind=SeedKind.CIDR, value="203.0.113.0/24")], [])
    assert overlay.cidrs == ["203.0.113.0/24"]


def test_asn_seed_is_parsed_to_int() -> None:
    overlay = build_org_scope_overlay([make_seed(kind=SeedKind.ASN, value="AS64500")], [])
    assert overlay.asns == [64500]


def test_cloud_account_seed_passes_through() -> None:
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.CLOUD_ACCOUNT, value="123456789012")], []
    )
    assert overlay.cloud_accounts == ["123456789012"]


def test_github_org_saas_tenant_brand_term_seeds_contribute_nothing() -> None:
    """Stored via `seed add` (matches the DoD's "seeds of every kind"), but
    none of them identify a network target — ScopeGuard has nothing to
    check them against until Part D §2's expansion step exists. An empty
    overlay contribution here is the point, not a bug a future change
    should silently start "fixing."
    """
    overlay = build_org_scope_overlay(
        [
            make_seed(kind=SeedKind.GITHUB_ORG, value="acme"),
            make_seed(kind=SeedKind.SAAS_TENANT, value="acme.okta.com"),
            make_seed(kind=SeedKind.BRAND_TERM, value="Acme Corporation"),
        ],
        [],
    )
    assert overlay.domains == []
    assert overlay.wildcards == []
    assert overlay.cidrs == []
    assert overlay.asns == []
    assert overlay.cloud_accounts == []
    assert overlay.exclude == []


def test_excluded_seed_goes_to_exclude_not_its_normal_bucket() -> None:
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="a.com", scope_action=ScopeAction.EXCLUDE)],
        [],
    )
    assert overlay.domains == []
    assert overlay.exclude == ["a.com"]


def test_excluded_wildcard_and_cidr_seeds_also_go_to_exclude() -> None:
    overlay = build_org_scope_overlay(
        [
            make_seed(kind=SeedKind.WILDCARD, value="*.a.com", scope_action=ScopeAction.EXCLUDE),
            make_seed(kind=SeedKind.CIDR, value="203.0.113.0/24", scope_action=ScopeAction.EXCLUDE),
        ],
        [],
    )
    assert overlay.exclude == ["*.a.com", "203.0.113.0/24"]
    assert overlay.wildcards == []
    assert overlay.cidrs == []


def test_excluded_asn_seed_is_stored_nowhere_scope_guard_checks() -> None:
    """ScopeGuard's exclude matcher is hostname/CIDR-shaped only — an
    excluded ASN seed has no bucket to land in. Documented limit, not a
    silent drop: this test is what would fail if that limit were quietly
    lifted without updating the seed-kind docs.
    """
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.ASN, value="AS64500", scope_action=ScopeAction.EXCLUDE)], []
    )
    assert overlay.asns == []
    assert overlay.exclude == []


def test_exclusion_row_domain_wildcard_cidr_go_to_exclude() -> None:
    overlay = build_org_scope_overlay(
        [],
        [
            make_exclusion(kind=SeedKind.APEX_DOMAIN, value="a.com"),
            make_exclusion(kind=SeedKind.WILDCARD, value="*.b.com"),
            make_exclusion(kind=SeedKind.CIDR, value="203.0.113.0/24"),
            make_exclusion(kind=SeedKind.IP, value="203.0.113.42"),
            make_exclusion(kind=SeedKind.URL, value="https://c.com/x"),
        ],
    )
    assert overlay.exclude == [
        "a.com",
        "*.b.com",
        "203.0.113.0/24",
        "203.0.113.42/32",
        "c.com",
    ]


def test_exclusion_row_asn_and_cloud_account_are_stored_not_enforced() -> None:
    overlay = build_org_scope_overlay(
        [],
        [
            make_exclusion(kind=SeedKind.ASN, value="AS64500"),
            make_exclusion(kind=SeedKind.CLOUD_ACCOUNT, value="123456789012"),
        ],
    )
    assert overlay.exclude == []
    assert overlay.asns == []
    assert overlay.cloud_accounts == []


def test_disabled_seeds_are_the_callers_job_not_this_functions() -> None:
    """`build_org_scope_overlay` has no `disabled_at` opinion — it reads
    whatever list it's given. Filtering disabled seeds out is
    `SeedRepository.list_for_org`'s default, exercised in that repo's own
    tests, not re-tested here.
    """
    overlay = build_org_scope_overlay(
        [make_seed(kind=SeedKind.APEX_DOMAIN, value="a.com", disabled_at=datetime.now(UTC))], []
    )
    assert overlay.domains == ["a.com"]
