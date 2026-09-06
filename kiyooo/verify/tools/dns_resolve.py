"""DNS resolution verification — asking a resolver,
the same passive-classification reasoning Stage 1's `dnsx` adapter uses
(you're asking a resolver, not touching the target). Uses the stdlib
resolver (`socket.getaddrinfo` via the event loop) rather than adding a
DNS library dependency.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kiyooo.verify.safety import ValidatedRequest

_RESOLVE_TIMEOUT_S = 5.0


def parse_addrinfo(results: list[Any]) -> dict[str, object]:
    """`results` is `socket.getaddrinfo`'s return shape — a 5-tuple whose
    last element (`sockaddr`) is itself a 2- or 4-tuple depending on
    address family. Typed `Any` deliberately: this is a boundary function
    over a stdlib return type, the same narrow-`Any` choice
    `enrich/cloud_aws.py`'s `_tags_from_list` makes for a similar reason.
    """
    addresses = sorted({str(sockaddr[0]) for *_rest, sockaddr in results})
    return {"addresses": addresses, "resolved": bool(addresses)}


async def run(validated: ValidatedRequest) -> dict[str, object]:
    hostname = validated.target
    record_type = str(validated.args["record_type"])
    family = socket.AF_INET if record_type == "A" else socket.AF_INET6

    loop = asyncio.get_running_loop()
    try:
        results = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM),
            timeout=_RESOLVE_TIMEOUT_S,
        )
    except (socket.gaierror, TimeoutError):
        results = []
    return parse_addrinfo(results)
