"""Full certificate chain verification — leaf plus
every intermediate the server actually presents. Python's stdlib `ssl`
module only exposes the leaf certificate from a live connection
(`SSLSocket.getpeercert()`); getting the intermediates needs OpenSSL's own
`SSL_get_peer_cert_chain`, which only pyOpenSSL exposes — the reason this
project takes a dependency on it for this one tool.

pyOpenSSL's `Connection` is a synchronous, blocking socket API with no
asyncio equivalent, so the actual handshake runs in a thread
(`asyncio.to_thread`), same pattern as this codebase's other
blocking-I/O-inside-async spots. Each returned certificate is converted via
`.to_cryptography()` immediately — pyOpenSSL's own `X509.get_subject()`/
`get_issuer()` accessors are deprecated in favor of the `cryptography`
library's X.509 API, which is what actually parses the fields here.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

from cryptography.x509.oid import NameOID
from OpenSSL import SSL

if TYPE_CHECKING:
    from cryptography import x509
    from OpenSSL.crypto import X509

    from kiyooo.verify.safety import ValidatedRequest

_HANDSHAKE_TIMEOUT_S = 5.0


def _name_cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _cert_summary(cert: x509.Certificate) -> dict[str, object]:
    return {
        "subject_cn": _name_cn(cert.subject),
        "issuer_cn": _name_cn(cert.issuer),
        "serial_number": str(cert.serial_number),
        "not_after": cert.not_valid_after_utc.isoformat(),
    }


def parse_chain(certs: list[X509]) -> dict[str, object]:
    summaries = [_cert_summary(cert.to_cryptography()) for cert in certs]
    return {"chain_length": len(certs), "chain": summaries}


def _fetch_chain_sync(host: str, port: int) -> list[X509]:
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda _conn, _cert, _errno, _depth, _ok: True)
    sock = socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT_S)
    conn = SSL.Connection(context, sock)
    try:
        conn.set_tlsext_host_name(host.encode())
        conn.set_connect_state()
        conn.do_handshake()
        chain = conn.get_peer_cert_chain()
        return list(chain) if chain else []
    finally:
        conn.close()
        sock.close()


async def run(validated: ValidatedRequest) -> dict[str, object]:
    host, _, port_str = validated.target.rpartition(":")
    port = int(port_str)
    certs = await asyncio.wait_for(
        asyncio.to_thread(_fetch_chain_sync, host, port), timeout=_HANDSHAKE_TIMEOUT_S + 2
    )
    return parse_chain(certs)
