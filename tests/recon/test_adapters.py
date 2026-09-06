"""Parser golden-file tests. Each fixture under tests/fixtures/recon/<tool>/ is
a hand-constructed, format-accurate sample modeled on that tool's documented
real output schema — not a literal capture. Running any of these tools live
against an arbitrary target requires scope authorization this test suite
doesn't have and CLAUDE.md's "no live network calls in the test suite" rule
wouldn't permit anyway; format accuracy is checked against each tool's own
`-json`/`-jsonl` documentation instead.
"""

from __future__ import annotations

from pathlib import Path

from kiyooo.db.models import AssetType, EvidenceKind
from kiyooo.recon.adapters.amass import AmassAdapter
from kiyooo.recon.adapters.censys import CensysAdapter
from kiyooo.recon.adapters.crtsh import CrtshAdapter
from kiyooo.recon.adapters.dnsx import DnsxAdapter
from kiyooo.recon.adapters.httpx import HttpxAdapter
from kiyooo.recon.adapters.katana import KatanaAdapter
from kiyooo.recon.adapters.naabu import NaabuAdapter
from kiyooo.recon.adapters.nuclei import NucleiAdapter
from kiyooo.recon.adapters.shodan import ShodanAdapter
from kiyooo.recon.adapters.subfinder import SubfinderAdapter
from kiyooo.recon.adapters.tlsx import TlsxAdapter

FIXTURES = Path(__file__).parent.parent / "fixtures" / "recon"


def _read(tool: str, filename: str = "sample.jsonl") -> bytes:
    return (FIXTURES / tool / filename).read_bytes()


def test_subfinder_parses_hosts_as_subdomains() -> None:
    evidence = SubfinderAdapter().parse(_read("subfinder"))
    assert len(evidence) == 3
    assert {e.asset_value for e in evidence} == {
        "www.example.com",
        "api.example.com",
        "mail.example.com",
    }
    assert all(e.asset_type == AssetType.SUBDOMAIN for e in evidence)
    assert all(e.kind == EvidenceKind.DNS_RECORD for e in evidence)


def test_subfinder_skips_malformed_and_blank_lines() -> None:
    raw = b'{"host":"a.example.com"}\n\nnot json at all\n{"host":"b.example.com"}\n'
    evidence = SubfinderAdapter().parse(raw)
    assert {e.asset_value for e in evidence} == {"a.example.com", "b.example.com"}


def test_subfinder_skips_lines_missing_host() -> None:
    raw = b'{"input":"example.com","source":"crtsh"}\n{"host":"real.example.com"}\n'
    evidence = SubfinderAdapter().parse(raw)
    assert len(evidence) == 1
    assert evidence[0].asset_value == "real.example.com"


def test_crtsh_splits_name_value_into_unique_subdomains() -> None:
    evidence = CrtshAdapter().parse(_read("crtsh", "sample.json"))
    values = {e.asset_value for e in evidence}
    assert values == {"www.example.com", "api.example.com", "example.com"}
    assert all(e.asset_type == AssetType.SUBDOMAIN for e in evidence)
    assert all(e.kind == EvidenceKind.TLS_CERT for e in evidence)


def test_crtsh_strips_wildcard_prefix() -> None:
    raw = b'[{"name_value": "*.example.com"}]'
    evidence = CrtshAdapter().parse(raw)
    assert evidence[0].asset_value == "example.com"


def test_crtsh_handles_empty_or_invalid_json() -> None:
    assert CrtshAdapter().parse(b"") == []
    assert CrtshAdapter().parse(b"not json") == []


def test_amass_parses_names_as_subdomains() -> None:
    evidence = AmassAdapter().parse(_read("amass"))
    assert {e.asset_value for e in evidence} == {"www.example.com", "dev.example.com"}
    assert all(e.asset_type == AssetType.SUBDOMAIN for e in evidence)


def test_dnsx_emits_one_evidence_per_resolved_ip() -> None:
    evidence = DnsxAdapter().parse(_read("dnsx"))
    # www.example.com -> 1 A record, api.example.com -> 2 A records = 3 total
    assert len(evidence) == 3
    assert {e.asset_value for e in evidence} == {
        "93.184.216.34",
        "93.184.216.35",
        "93.184.216.36",
    }
    assert all(e.asset_type == AssetType.IP for e in evidence)


def test_naabu_emits_host_port_as_tcp_service() -> None:
    evidence = NaabuAdapter().parse(_read("naabu"))
    assert {e.asset_value for e in evidence} == {"93.184.216.34:443", "93.184.216.34:80"}
    assert all(e.asset_type == AssetType.TCP_SERVICE for e in evidence)
    assert all(e.kind == EvidenceKind.PORT_BANNER for e in evidence)


def test_httpx_emits_url_as_http_service() -> None:
    evidence = HttpxAdapter().parse(_read("httpx"))
    assert {e.asset_value for e in evidence} == {
        "https://www.example.com",
        "https://api.example.com",
    }
    assert all(e.asset_type == AssetType.HTTP_SERVICE for e in evidence)
    assert all(e.kind == EvidenceKind.HTTP_RESPONSE for e in evidence)


def test_tlsx_emits_host_port_as_cert() -> None:
    evidence = TlsxAdapter().parse(_read("tlsx"))
    assert {e.asset_value for e in evidence} == {
        "www.example.com:443",
        "api.example.com:443",
    }
    assert all(e.asset_type == AssetType.CERT for e in evidence)
    assert all(e.kind == EvidenceKind.TLS_CERT for e in evidence)


def test_katana_emits_crawled_endpoint_as_url() -> None:
    evidence = KatanaAdapter().parse(_read("katana"))
    assert {e.asset_value for e in evidence} == {
        "https://www.example.com/about",
        "https://www.example.com/contact",
    }
    assert all(e.asset_type == AssetType.URL for e in evidence)


def test_nuclei_emits_matched_at_as_url_with_full_finding_in_content() -> None:
    evidence = NucleiAdapter().parse(_read("nuclei"))
    assert {e.asset_value for e in evidence} == {
        "https://www.example.com",
        "https://api.example.com/admin/login",
    }
    assert all(e.kind == EvidenceKind.NUCLEI_RESULT for e in evidence)
    panel_finding = next(e for e in evidence if "admin" in e.asset_value)
    assert panel_finding.content["template-id"] == "exposed-panel-login"


def test_nuclei_always_excludes_dos_intrusive_fuzz_tags() -> None:
    """The one adapter where the command line itself is a safety control
    . This test exists so nobody can quietly drop the
    flag in a refactor without a test noticing.
    """
    from kiyooo.recon.adapters.nuclei import _EXCLUDED_TAGS

    assert set(_EXCLUDED_TAGS) == {"dos", "intrusive", "fuzz"}
    argv = NucleiAdapter()._argv([])
    assert "-etags" in argv
    etags_value = argv[argv.index("-etags") + 1]
    assert set(etags_value.split(",")) == {"dos", "intrusive", "fuzz"}


def test_shodan_emits_one_evidence_per_open_port() -> None:
    evidence = ShodanAdapter().parse(_read("shodan", "sample.json"))
    assert {e.asset_value for e in evidence} == {
        "93.184.216.34:443",
        "93.184.216.34:80",
    }
    assert all(e.asset_type == AssetType.TCP_SERVICE for e in evidence)


def test_shodan_handles_empty_or_invalid_json() -> None:
    assert ShodanAdapter().parse(b"") == []
    assert ShodanAdapter().parse(b"not json") == []


def test_censys_emits_one_evidence_per_service() -> None:
    evidence = CensysAdapter().parse(_read("censys", "sample.json"))
    assert {e.asset_value for e in evidence} == {
        "93.184.216.34:443",
        "93.184.216.34:22",
    }
    assert all(e.asset_type == AssetType.TCP_SERVICE for e in evidence)


def test_censys_handles_empty_or_invalid_json() -> None:
    assert CensysAdapter().parse(b"") == []
    assert CensysAdapter().parse(b"not json") == []
