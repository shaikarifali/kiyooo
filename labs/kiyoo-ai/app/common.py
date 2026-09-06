"""Shared helpers for every decoy service in the kiyoo-ai lab.

Every response in this lab is decoy-grade, never exploit-grade: it emits
exactly the fingerprint a real kiyooo scan looks for, and nothing behind
it. No service in this package executes
attacker-supplied input, writes outside its own process memory, or
implements the dangerous operation its banner advertises.
"""

from __future__ import annotations

import os

LAB_DOMAIN = os.environ.get("KIYOO_LAB_DOMAIN", "kiyoo-ai.lab")

LAB_NOTICE = (
    "This is a deliberately vulnerable security-research lab for the "
    "kiyooo project (https://github.com/). All data here is synthetic. "
    "No destructive action, code execution, or data exfiltration is "
    "implemented behind this endpoint — see the design doc section 0."
)


def host(subdomain: str) -> str:
    """`host("mcp-docs")` -> `"mcp-docs.kiyoo-ai.lab"` (or whatever
    KIYOO_LAB_DOMAIN is set to — the real deployment sets it to the
    public lab domain; local/CI runs use the .lab default so this never
    collides with a real hostname).
    """
    return f"{subdomain}.{LAB_DOMAIN}"


def decoy_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    # HTTP header values must be latin-1 encodable — no em-dash here.
    headers = {"X-Lab-Notice": "decoy - see /_lab/notice"}
    if extra:
        headers.update(extra)
    return headers
