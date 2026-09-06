from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

from kiyooo.verify.tools.cert_chain import parse_chain


def _self_signed_cert(common_name: str) -> crypto.X509:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return crypto.X509.from_cryptography(cert)


def test_parse_chain_single_cert() -> None:
    cert = _self_signed_cert("app.example.com")
    content = parse_chain([cert])
    assert content["chain_length"] == 1
    entry = content["chain"][0]
    assert entry["subject_cn"] == "app.example.com"
    assert entry["issuer_cn"] == "app.example.com"  # self-signed
    assert entry["serial_number"] == "1"
    assert entry["not_after"] is not None


def test_parse_chain_multiple_certs_preserves_order() -> None:
    leaf = _self_signed_cert("app.example.com")
    intermediate = _self_signed_cert("Intermediate CA")
    content = parse_chain([leaf, intermediate])
    assert content["chain_length"] == 2
    assert content["chain"][0]["subject_cn"] == "app.example.com"
    assert content["chain"][1]["subject_cn"] == "Intermediate CA"


def test_parse_chain_empty() -> None:
    content = parse_chain([])
    assert content["chain_length"] == 0
    assert content["chain"] == []
