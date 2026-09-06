"""Parser tests use a hand-constructed sample matching Prowler's documented
JSON-OCSF (OCSF Detection Finding v1.1.0) schema — there is no live Prowler
binary or cloud account in this sandbox to record a real run against, same
honest limitation `ingest/adapters/qualys.py`/`wiz.py` document for their
stages. Unlike those, the OCSF schema itself is a published, versioned
standard (not vendor-proprietary), so this fixture is built directly from
that spec rather than guessed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.prowler import (
    ProwlerConfig,
    ProwlerRunError,
    parse_ocsf_finding,
    parse_prowler_output,
    run_prowler,
)

_FAIL_RECORD = {
    "status_code": "FAIL",
    "status_detail": "Bucket acme-uploads-prod has public read access",
    "severity": "Critical",
    "message": "S3 Bucket acme-uploads-prod has public access",
    "metadata": {"event_code": "s3_bucket_public_access"},
    "finding_info": {
        "uid": "prowler-aws-s3_bucket_public_access-acme-uploads-prod",
        "title": "Check S3 Bucket for public access",
        "desc": "This check ensures S3 buckets are not publicly accessible.",
    },
    "cloud": {
        "provider": "aws",
        "region": "us-east-1",
        "account": {"uid": "123456789012"},
    },
    "resources": [
        {
            "uid": "arn:aws:s3:::acme-uploads-prod",
            "name": "acme-uploads-prod",
            "type": "AwsS3Bucket",
            "region": "us-east-1",
        }
    ],
    "remediation": {"desc": "Remove public read/write ACLs and bucket policy grants."},
}

_PASS_RECORD = {
    **_FAIL_RECORD,
    "status_code": "PASS",
    "status_detail": "Bucket acme-internal-logs is not publicly accessible",
}


def test_parse_ocsf_finding_maps_fail_record() -> None:
    imported = parse_ocsf_finding(_FAIL_RECORD)
    assert imported is not None
    assert imported.external_id == "s3_bucket_public_access:arn:aws:s3:::acme-uploads-prod"
    assert imported.vendor_issue_type == "s3_bucket_public_access"
    assert imported.title == "Check S3 Bucket for public access"
    assert imported.vendor_severity == "Critical"
    assert imported.asset_type == AssetType.CLOUD_RESOURCE
    assert imported.asset_value == "arn:aws:s3:::acme-uploads-prod"
    assert imported.evidence_content["account_id"] == "123456789012"
    assert imported.evidence_content["region"] == "us-east-1"
    assert imported.raw_payload == _FAIL_RECORD


def test_parse_ocsf_finding_ignores_pass_record() -> None:
    assert parse_ocsf_finding(_PASS_RECORD) is None


def test_parse_ocsf_finding_handles_missing_optional_fields() -> None:
    sparse = {"status_code": "FAIL"}
    imported = parse_ocsf_finding(sparse)
    assert imported is not None
    assert imported.vendor_issue_type == "unknown-check"
    assert imported.asset_value == "unknown-resource"
    assert imported.evidence_content["account_id"] == "unknown-account"


def test_parse_prowler_output_filters_to_only_failures() -> None:
    raw = json.dumps([_FAIL_RECORD, _PASS_RECORD, _FAIL_RECORD]).encode()
    findings = parse_prowler_output(raw)
    assert len(findings) == 2
    assert all(f.vendor_issue_type == "s3_bucket_public_access" for f in findings)


def test_parse_prowler_output_accepts_single_object_not_just_array() -> None:
    raw = json.dumps(_FAIL_RECORD).encode()
    findings = parse_prowler_output(raw)
    assert len(findings) == 1


def test_config_rejects_shell_metacharacters_in_extra_args() -> None:
    with pytest.raises(ValueError, match="shell metacharacter"):
        ProwlerConfig(provider="aws", extra_args=["--profile", "prod; rm -rf /"])


async def test_run_prowler_raises_prowler_run_error_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The `prowler` binary not being installed/on PATH is an expected,
    common failure — the API layer only catches `ProwlerRunError` (and a
    couple of others), so this must not leak as a raw `FileNotFoundError`
    and turn into an unhandled 500. Caught live: this exact bug reached a
    real 500 in the browser before this wrapping was added.
    """

    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr("kiyooo.ingest.adapters.prowler.run_subprocess", fake_run_subprocess)
    with pytest.raises(ProwlerRunError, match="prowler binary not found"):
        await run_prowler(ProwlerConfig(provider="aws"))


async def test_run_prowler_reads_report_file(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        out_dir = Path(argv[argv.index("-o") + 1])
        (out_dir / "report.ocsf.json").write_bytes(b"[]")
        return 0, b"", b""

    monkeypatch.setattr("kiyooo.ingest.adapters.prowler.run_subprocess", fake_run_subprocess)
    raw = await run_prowler(ProwlerConfig(provider="aws"))
    assert raw == b"[]"


async def test_run_prowler_raises_when_report_file_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        return 1, b"", b"prowler: command not found"

    monkeypatch.setattr("kiyooo.ingest.adapters.prowler.run_subprocess", fake_run_subprocess)
    with pytest.raises(ProwlerRunError, match="command not found"):
        await run_prowler(ProwlerConfig(provider="aws"))
