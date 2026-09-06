from __future__ import annotations

import socket

from kiyooo.verify.tools.dns_resolve import parse_addrinfo


def test_parse_addrinfo_extracts_unique_sorted_addresses() -> None:
    results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),  # duplicate
    ]
    content = parse_addrinfo(results)
    assert content["addresses"] == ["93.184.216.34", "93.184.216.35"]
    assert content["resolved"] is True


def test_parse_addrinfo_empty_results_is_unresolved() -> None:
    content = parse_addrinfo([])
    assert content["addresses"] == []
    assert content["resolved"] is False
