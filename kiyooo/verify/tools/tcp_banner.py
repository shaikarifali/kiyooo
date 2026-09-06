"""TCP banner grab verification: connect and read
whatever the service sends unprompted — no protocol handshake, no
authentication attempted, nothing written to the socket beyond the TCP
handshake itself.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.verify.safety import ValidatedRequest

_CONNECT_TIMEOUT_S = 5.0
_READ_TIMEOUT_S = 3.0
_MAX_BANNER_BYTES = 1024


def parse_banner(raw: bytes) -> dict[str, object]:
    return {
        "banner": raw.decode("utf-8", errors="replace").strip(),
        "byte_length": len(raw),
    }


async def run(validated: ValidatedRequest) -> dict[str, object]:
    host, _, port_str = validated.target.rpartition(":")
    port = int(port_str)

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=_CONNECT_TIMEOUT_S
    )
    try:
        try:
            raw = await asyncio.wait_for(reader.read(_MAX_BANNER_BYTES), timeout=_READ_TIMEOUT_S)
        except TimeoutError:
            raw = b""
    finally:
        writer.close()
        await writer.wait_closed()
    return parse_banner(raw)
