"""`db` — a MySQL 5.7.29 handshake decoy on TCP.

The only non-HTTP listener in this lab, kept deliberately tiny: it writes
one real MySQL protocol handshake packet and closes. No auth handler, no
query parser, no data — this is a banner, not a database. Run standalone
(`python -m app.services.db_handshake`), separate from the Host-routed
FastAPI app since Starlette's `Host()` routing only applies to HTTP.
"""

from __future__ import annotations

import asyncio
import struct

_SERVER_VERSION = b"5.7.29-kiyoo-lab\x00"
_CONNECTION_ID = 1
_AUTH_PLUGIN_DATA_1 = b"labfake1"  # 8 bytes
_AUTH_PLUGIN_DATA_2 = b"labfake0000\x00"  # 13 bytes incl. terminator
_CAPABILITY_FLAGS = 0xFFFF  # decorative — no auth handler exists behind this
_CHARSET = 0x21  # utf8_general_ci
_STATUS_FLAGS = 0x0002


def _build_handshake_packet() -> bytes:
    payload = bytearray()
    payload += b"\x0a"  # protocol version 10
    payload += _SERVER_VERSION
    payload += struct.pack("<I", _CONNECTION_ID)
    payload += _AUTH_PLUGIN_DATA_1
    payload += b"\x00"  # filler
    payload += struct.pack("<H", _CAPABILITY_FLAGS & 0xFFFF)
    payload += bytes([_CHARSET])
    payload += struct.pack("<H", _STATUS_FLAGS)
    payload += struct.pack("<H", (_CAPABILITY_FLAGS >> 16) & 0xFFFF)
    payload += bytes([21])  # auth plugin data length
    payload += b"\x00" * 10  # reserved
    payload += _AUTH_PLUGIN_DATA_2
    payload += b"mysql_native_password\x00"

    header = struct.pack("<I", len(payload))[:3] + b"\x00"  # sequence id 0
    return header + bytes(payload)


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(_build_handshake_packet())
        await writer.drain()
    finally:
        writer.close()


async def main(host: str = "0.0.0.0", port: int = 3306) -> None:
    server = await asyncio.start_server(_handle, host, port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
