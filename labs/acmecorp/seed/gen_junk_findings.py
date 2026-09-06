#!/usr/bin/env python3
"""Generates labs/acmecorp/seed/junk-findings.csv — Stage 12's
"200 seeded junk findings from a fake scanner import." Most rows are noise
a generic vendor scanner reports that has no `vendor_mapping.yaml` entry
(surfaces via `kiyooo ingest unmapped` as a work item, never silently
dropped) or maps onto an asset a compensating control already covers. The
demo point the design doc calls out explicitly: correctly discarding 200 things
and explaining why, not finding one more bug, is what a review board
actually wants to see (§0.5's Forrester critique).

Run: uv run python gen_junk_findings.py > junk-findings.csv
"""

from __future__ import annotations

import csv
import sys

_NOISY_ISSUE_TYPES = [
    "TLS1.2-Supported",
    "HSTS-Header-Present-But-Short-Max-Age",
    "Server-Header-Discloses-Version",
    "Missing-X-Content-Type-Options",
    "Cookie-Missing-SameSite-Attribute",
    "Directory-Listing-Disabled-Confirmed",
    "TLS-Session-Resumption-Enabled",
    "HTTP-OPTIONS-Method-Enabled",
    "Self-Signed-Cert-On-Internal-Host",
    "Outdated-TLS-Cipher-Suite-Available",
]

# One row per 20 maps onto something real, so the demo can show a handful
# of genuine (if already-mitigated or low-severity) signals surviving
# triage alongside the noise, not a corpus that's 100% discardable by
# construction.
_REAL_ISSUE_TYPES = ["sql-db-exposed", "CVE-DB-1234"]


def main() -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow(["ID", "Host", "Type", "Title", "Severity"])

    row_id = 1
    for i in range(190):
        issue_type = _NOISY_ISSUE_TYPES[i % len(_NOISY_ISSUE_TYPES)]
        host = f"host-{(i % 40) + 1:03d}.acmecorp.internal"
        writer.writerow([f"scan-{row_id}", host, issue_type, issue_type.replace("-", " "), "Info"])
        row_id += 1

    for i in range(10):
        issue_type = _REAL_ISSUE_TYPES[i % len(_REAL_ISSUE_TYPES)]
        writer.writerow(
            [
                f"scan-{row_id}",
                "mysql-exposed.acmecorp.lab:3306",
                issue_type,
                "MySQL exposed",
                "High",
            ]
        )
        row_id += 1


if __name__ == "__main__":
    main()
