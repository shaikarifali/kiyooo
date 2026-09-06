"""TLS handshake verification — a real handshake with
no client certificate presented, to observe what the server actually
requires. This is the live probe `detect/predicates.py`'s
`tls_handshake_requires_client_cert` predicate (Stage 4) has been waiting
on — no adapter populated `requires_client_cert` in evidence until now,
since detecting mTLS enforcement needs an active differential probe, not
passive `tlsx` output.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.verify.safety import ValidatedRequest

_HANDSHAKE_TIMEOUT_S = 5.0

# A server that mandates a client certificate rejects a handshake carrying
# none with one of these alerts — OpenSSL's wording varies by version, so
# this matches on the phrases that are stable across it.
_CLIENT_CERT_REQUIRED_MARKERS = ("certificate required", "handshake failure")


def parse_handshake_error(message: str) -> dict[str, object]:
    lowered = message.lower()
    requires_client_cert = any(marker in lowered for marker in _CLIENT_CERT_REQUIRED_MARKERS)
    return {"requires_client_cert": requires_client_cert, "handshake_error": message}


def parse_handshake_success(cert: dict[str, object] | None) -> dict[str, object]:
    return {"requires_client_cert": False, "peer_cert_present": cert is not None}


async def run(validated: ValidatedRequest) -> dict[str, object]:
    host, _, port_str = validated.target.rpartition(":")
    port = int(port_str)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=_HANDSHAKE_TIMEOUT_S,
        )
    except ssl.SSLError as exc:
        return parse_handshake_error(str(exc))

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() if ssl_object is not None else None
        return parse_handshake_success(cert)
    finally:
        writer.close()
        await writer.wait_closed()
