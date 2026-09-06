from __future__ import annotations

from kiyooo.verify.tools.tcp_banner import parse_banner


def test_parse_banner_decodes_text() -> None:
    content = parse_banner(b"220 mail.example.com ESMTP ready\r\n")
    assert content["banner"] == "220 mail.example.com ESMTP ready"
    assert content["byte_length"] == 34


def test_parse_banner_handles_binary_data() -> None:
    content = parse_banner(b"\x00\x01\xff\xfe")
    assert content["byte_length"] == 4
    assert isinstance(content["banner"], str)  # replaced, never raises


def test_parse_banner_empty_read() -> None:
    content = parse_banner(b"")
    assert content["banner"] == ""
    assert content["byte_length"] == 0
