from __future__ import annotations

from kiyooo.verify.safety import DENIED_NUCLEI_TAGS
from kiyooo.verify.tools.nuclei_single import build_argv, parse_output


def test_parse_output_matched() -> None:
    raw = (
        b'{"template-id":"tech-detect","info":{"name":"Tech Detection",'
        b'"severity":"info"},"host":"https://app.example.com",'
        b'"matched-at":"https://app.example.com","type":"http"}\n'
    )
    content = parse_output(raw)
    assert content["matched"] is True
    assert content["template_id"] == "tech-detect"
    assert content["matched_at"] == "https://app.example.com"


def test_parse_output_no_match_empty_output() -> None:
    assert parse_output(b"") == {"matched": False}


def test_parse_output_skips_malformed_lines() -> None:
    raw = b"not json\n" + b'{"template-id":"tech-detect","host":"x","matched-at":"x"}\n'
    content = parse_output(raw)
    assert content["matched"] is True
    assert content["template_id"] == "tech-detect"


def test_build_argv_always_excludes_denied_tags() -> None:
    argv = build_argv("nuclei", "app.example.com", "tech-detect")
    assert "-etags" in argv
    etags_value = argv[argv.index("-etags") + 1]
    assert set(etags_value.split(",")) == set(DENIED_NUCLEI_TAGS)


def test_build_argv_passes_target_and_template_id() -> None:
    argv = build_argv("nuclei", "app.example.com", "tech-detect")
    assert argv[argv.index("-target") + 1] == "app.example.com"
    assert argv[argv.index("-id") + 1] == "tech-detect"
