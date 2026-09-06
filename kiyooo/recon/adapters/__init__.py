"""Importing this package registers every adapter kiyooo ships (each module's
`@register` decorator runs on import). `orchestrator.py` imports this package
once per `Orchestrator.run()` call; nothing else needs to.
"""

from __future__ import annotations

from kiyooo.recon.adapters import (
    amass,
    censys,
    crtsh,
    dnsx,
    httpx,
    katana,
    naabu,
    nuclei,
    shodan,
    subfinder,
    tlsx,
)

__all__ = [
    "amass",
    "censys",
    "crtsh",
    "dnsx",
    "httpx",
    "katana",
    "naabu",
    "nuclei",
    "shodan",
    "subfinder",
    "tlsx",
]
