from __future__ import annotations

from pathlib import Path

from kiyooo.db.models import AssetType
from kiyooo.enrich.ownership.sources import (
    match_codeowner,
    parse_codeowners,
    parse_terraform_state,
    terraform_codeowners,
)
from tests.enrich.factories import make_asset

FIXTURES = Path(__file__).parent.parent / "fixtures" / "enrich"


def _terraform_resources():
    return parse_terraform_state((FIXTURES / "terraform.tfstate.json").read_bytes())


def _codeowners():
    return parse_codeowners((FIXTURES / "CODEOWNERS").read_bytes())


def test_parse_terraform_state_extracts_known_resource_types() -> None:
    resources = _terraform_resources()
    values = {r.asset_value for r in resources}
    assert values == {"93.184.216.34", "acmecorp-reports"}


def test_parse_terraform_state_skips_unsupported_resource_types() -> None:
    resources = _terraform_resources()
    # aws_vpc is in the fixture but not in _TERRAFORM_VALUE_ATTRS
    assert not any("vpc" in r.asset_value for r in resources)


def test_parse_terraform_state_captures_module_path() -> None:
    resources = _terraform_resources()
    by_value = {r.asset_value: r.module_path for r in resources}
    assert by_value["93.184.216.34"] == "network"
    assert by_value["acmecorp-reports"] == "data-platform"


def test_parse_codeowners_extracts_pattern_owner_pairs() -> None:
    pairs = _codeowners()
    assert ("*", "platform-team") in pairs
    assert ("network/*", "netops") in pairs
    assert ("data-platform/*", "data-platform") in pairs


def test_match_codeowner_prefers_specific_pattern_over_fallback() -> None:
    codeowners = _codeowners()
    assert match_codeowner("network", codeowners) == "netops"
    assert match_codeowner("data-platform", codeowners) == "data-platform"


def test_match_codeowner_falls_back_to_wildcard() -> None:
    codeowners = _codeowners()
    assert match_codeowner("some-other-module", codeowners) == "platform-team"


def test_terraform_codeowners_source_end_to_end() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    candidate = terraform_codeowners(asset, _terraform_resources(), _codeowners())
    assert candidate is not None
    assert candidate.owner_ref == "netops"
    assert candidate.confidence == 0.90


def test_terraform_codeowners_no_matching_resource_returns_none() -> None:
    asset = make_asset(AssetType.IP, "10.0.0.99")
    assert terraform_codeowners(asset, _terraform_resources(), _codeowners()) is None
