"""Parser tests use hand-constructed samples matching TruffleHog's
documented JSON finding schema (SourceMetadata.Data.Git, DetectorName,
Verified, Raw/Redacted/ExtraData) — there is no live TruffleHog binary or
repo in this sandbox to record a real run against, same honest limitation
Prowler's/Trivy's tests document.
"""

from __future__ import annotations

import json

import pytest

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.trufflehog import (
    TrufflehogConfig,
    TrufflehogRunError,
    parse_trufflehog_output,
    parse_trufflehog_record,
    run_trufflehog,
)

_RECORD = {
    "SourceMetadata": {
        "Data": {
            "Git": {
                "commit": "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
                "file": "config/keys.py",
                "email": "dev@acmecorp.example",
                "repository": "https://github.com/acmecorp/internal-api",
                "timestamp": "2026-06-16 10:17:40 -0700 PDT",
                "line": 4,
            }
        }
    },
    "SourceID": 0,
    "SourceType": 16,
    "SourceName": "trufflehog - git",
    "DetectorType": 2,
    "DetectorName": "AWS",
    "DetectorDescription": "AWS access key",
    "DecoderName": "PLAIN",
    "Verified": True,
    "Raw": "AKIAYVP4CIPPERUVIFXG",
    "RawV2": "AKIAYVP4CIPPERUVIFXG:secretvalue",
    "Redacted": "AKIAYVP4CIPPERUVIFXG",
    "ExtraData": {"account": "595918472158"},
    "StructuredData": None,
}


def test_parse_trufflehog_record_extracts_expected_fields() -> None:
    imported = parse_trufflehog_record(_RECORD)
    assert imported.vendor_issue_type == "trufflehog-verified-secret"
    assert imported.vendor_severity == "critical"
    assert imported.asset_type == AssetType.REPO
    assert imported.asset_value == "https://github.com/acmecorp/internal-api"
    assert "AWS" in imported.title
    assert imported.evidence_content["detector_name"] == "AWS"
    assert imported.evidence_content["file"] == "config/keys.py"
    assert imported.evidence_content["commit"] == "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca"


def test_parse_trufflehog_record_never_carries_raw_secret_fields() -> None:
    """The single most important property of this adapter: Raw/RawV2/
    Redacted/ExtraData/StructuredData must never appear anywhere in the
    resulting ImportedFinding — not in evidence_content, not in
    raw_payload. This is invariant #7, checked directly rather than
    trusted.
    """
    imported = parse_trufflehog_record(_RECORD)
    forbidden = ("AKIAYVP4CIPPERUVIFXG", "secretvalue", "595918472158")

    evidence_str = json.dumps(imported.evidence_content)
    payload_str = json.dumps(imported.raw_payload)
    for secret in forbidden:
        assert secret not in evidence_str, f"{secret!r} leaked into evidence_content"
        assert secret not in payload_str, f"{secret!r} leaked into raw_payload"

    for unsafe_key in ("Raw", "RawV2", "Redacted", "ExtraData", "StructuredData"):
        assert unsafe_key not in imported.raw_payload


def test_parse_trufflehog_output_handles_jsonl() -> None:
    raw = (json.dumps(_RECORD) + "\n" + json.dumps(_RECORD)).encode()
    findings = parse_trufflehog_output(raw)
    assert len(findings) == 2


def test_parse_trufflehog_output_handles_json_array_fallback() -> None:
    raw = json.dumps([_RECORD, _RECORD]).encode()
    findings = parse_trufflehog_output(raw)
    assert len(findings) == 2


def test_parse_trufflehog_output_empty_stdout_returns_no_findings() -> None:
    assert parse_trufflehog_output(b"") == []
    assert parse_trufflehog_output(b"   \n  ") == []


def test_config_rejects_shell_metacharacters_in_extra_args() -> None:
    with pytest.raises(ValueError, match="shell metacharacter"):
        TrufflehogConfig(repo_url="https://github.com/a/b.git", extra_args=["--foo; rm -rf /"])


async def test_run_trufflehog_substitutes_credential_into_url_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_REPO_TOKEN", "tok_abc123")
    seen_argv: list[str] = []

    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        seen_argv.extend(argv)
        return 0, b"", b""

    monkeypatch.setattr("kiyooo.ingest.adapters.trufflehog.run_subprocess", fake_run_subprocess)
    config = TrufflehogConfig(
        repo_url="https://{credential}@github.com/acmecorp/internal-api.git",
        credential_ref="env:TEST_REPO_TOKEN",
    )
    await run_trufflehog(config)
    assert "https://tok_abc123@github.com/acmecorp/internal-api.git" in seen_argv


async def test_run_trufflehog_disables_self_update(monkeypatch: pytest.MonkeyPatch) -> None:
    """Caught live: a real `trufflehog` binary in a locked-down environment
    failed with "cannot move binary" when it tried to self-update mid-run.
    `--no-update` must always be passed, not left to `extra_args`.
    """
    seen_argv: list[str] = []

    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        seen_argv.extend(argv)
        return 0, b"", b""

    monkeypatch.setattr("kiyooo.ingest.adapters.trufflehog.run_subprocess", fake_run_subprocess)
    await run_trufflehog(TrufflehogConfig(repo_url="https://github.com/a/b.git"))
    assert "--no-update" in seen_argv


async def test_run_trufflehog_raises_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr("kiyooo.ingest.adapters.trufflehog.run_subprocess", fake_run_subprocess)
    with pytest.raises(TrufflehogRunError, match="trufflehog binary not found"):
        await run_trufflehog(TrufflehogConfig(repo_url="https://github.com/a/b.git"))
