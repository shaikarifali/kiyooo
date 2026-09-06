"""CISA Known Exploited Vulnerabilities (KEV) catalog.

"CVE relevance is gated on known exploited + EPSS score, not CVSS" — this
module answers the "known exploited" half (see `epss.py` for the other). The
catalog is CISA's own public, read-only feed about vulnerabilities in
general — not anything belonging to a scanned target — so fetching it isn't
gated by `ScopeGuard` the way recon adapters are.

`parse_kev_catalog` is pure (bytes in, catalog out) so it's testable against
a recorded fixture with no live network call in the test suite, per this
project's testing rule; only `fetch_kev_catalog` touches the network, and
nothing in `tests/` calls it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TIMEOUT_S = 30.0


@dataclass(frozen=True, slots=True)
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    known_ransomware_use: bool


@dataclass(frozen=True, slots=True)
class KevCatalog:
    entries: dict[str, KevEntry]
    catalog_version: str
    date_released: str

    def is_known_exploited(self, cve_id: str) -> bool:
        return cve_id.upper() in self.entries


def parse_kev_catalog(raw: bytes) -> KevCatalog:
    payload = json.loads(raw)
    entries: dict[str, KevEntry] = {}
    for item in payload.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        cve_id = cve_id.upper()
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor_project=item.get("vendorProject", ""),
            product=item.get("product", ""),
            vulnerability_name=item.get("vulnerabilityName", ""),
            date_added=item.get("dateAdded", ""),
            known_ransomware_use=item.get("knownRansomwareCampaignUse", "Unknown") == "Known",
        )
    return KevCatalog(
        entries=entries,
        catalog_version=payload.get("catalogVersion", ""),
        date_released=payload.get("dateReleased", ""),
    )


async def fetch_kev_catalog(client: httpx.AsyncClient) -> KevCatalog:
    resp = await client.get(KEV_FEED_URL, timeout=_TIMEOUT_S)
    resp.raise_for_status()
    return parse_kev_catalog(resp.content)
