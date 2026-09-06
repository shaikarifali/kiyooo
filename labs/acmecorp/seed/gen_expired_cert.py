#!/usr/bin/env python3
"""Generates a self-signed, deliberately-expired TLS cert covering 40
vhosts (app01.acmecorp.lab .. app40.acmecorp.lab) — Stage 12's
"expired cert shared by 40 vhosts" clustering demo: kiyooo's fingerprint
rule (normalize/fingerprint.py) clusters all 40 findings into one
cluster_id because they share the same cert serial, so the demo shows 40
findings collapsing into 1 ticket.

Uses `cryptography` directly (not `openssl req -x509`, which has no
portable not_before/not_after override in every OpenSSL build) so the
cert's expiry is deterministic regardless of when `make lab-up` runs: it
expired in the past and stays expired.

Run via: uv run --with cryptography python gen_expired_cert.py <outdir>
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_VHOST_COUNT = 40
_EXPIRED_SINCE = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
_ISSUED = datetime.datetime(2023, 1, 1, tzinfo=datetime.UTC)


def main(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    hostnames = [f"app{i:02d}.acmecorp.lab" for i in range(1, _VHOST_COUNT + 1)]
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_ISSUED)
        .not_valid_after(_EXPIRED_SINCE)
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    (outdir / "expired.key").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (outdir / "expired.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(
        f"wrote {outdir / 'expired.crt'} — expired {_EXPIRED_SINCE.date()}, {len(hostnames)} SANs"
    )


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "certs"))
