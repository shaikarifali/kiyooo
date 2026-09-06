"""TruffleHog — wraps trufflesecurity/trufflehog (the
OSS engine, AGPL-3.0, ~25.7k GitHub stars) rather than reimplementing secret
scanning ourselves (§0's non-goal). Invoked as an external subprocess whose
output is parsed, never linked into or redistributed with kiyooo — AGPL-3.0
applies to TruffleHog's own source, not to this codebase, the same
subprocess-boundary reasoning `prowler.py` documents.

Run with `--only-verified`, which makes TruffleHog live-check each
candidate credential against its actual provider (AWS STS, GitHub's API,
etc.) before reporting it — a real API call using the org's own possibly-
compromised credential, made *to confirm the org's own secret is still
live*, not to attack a third party (contrast with invariant #1: this
verifies exposure of the org's own infrastructure, exactly like Prowler/
Trivy call the org's own cloud/registry APIs with org-supplied credentials).
This is also a genuine false-positive filter built into the scanner itself:
an already-rotated key never becomes a candidate finding at all.

**Security-critical detail — read before touching this file.** TruffleHog's
own docs are explicit: "Do not expose Raw, RawV2, Redacted, or ExtraData in
report output, metrics, or logs — they may contain secrets" (`Redacted` is
NOT guaranteed fully redacted for every detector). This adapter never
copies a TruffleHog record's `Raw`/`RawV2`/`Redacted`/`ExtraData`/
`StructuredData` fields anywhere — not into evidence, not into
`raw_payload`. `raw_payload` here is a hand-built, already-sanitized dict,
not "the vendor record verbatim" the way every other adapter's is. This is
on top of, not instead of, the generic secret redaction the evidence writer
already runs on every ingest source (invariant #7 defense in depth).
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, field_validator

from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding
from kiyooo.llm.credentials import resolve_credential
from kiyooo.recon.adapters._subprocess import run_subprocess

_SHELL_METACHARACTERS = (";", "|", "&", "$(", "`", "\n")
_VERIFIED_SECRET_ISSUE_TYPE = "trufflehog-verified-secret"
# Never carry these into evidence/raw_payload — see module docstring.
_UNSAFE_FIELDS = frozenset({"Raw", "RawV2", "Redacted", "ExtraData", "StructuredData"})


class TrufflehogRunError(RuntimeError):
    pass


class TrufflehogConfig(BaseModel):
    """`repo_url` may contain a literal `{credential}` placeholder (e.g.
    `https://{credential}@github.com/acmecorp/internal-api.git`) filled in
    from `credential_ref` at run time for a private repo — same
    template-with-placeholder convention as `GenericRestConfig.
    auth_value_template`. A public repo needs no credential at all.
    """

    repo_url: str = Field(min_length=1)
    credential_ref: str | None = None
    extra_args: list[str] = Field(default_factory=list)

    @field_validator("extra_args")
    @classmethod
    def _no_shell_metacharacters(cls, value: list[str]) -> list[str]:
        for arg in value:
            if any(ch in arg for ch in _SHELL_METACHARACTERS):
                raise ValueError(f"extra_arg {arg!r} contains a shell metacharacter")
        return value


def _resolved_repo_url(config: TrufflehogConfig) -> str:
    if config.credential_ref is None:
        return config.repo_url
    credential = resolve_credential(config.credential_ref) or ""
    return config.repo_url.format(credential=credential)


async def run_trufflehog_filesystem(path: str) -> bytes:
    """Runs TruffleHog's `filesystem` subcommand against a local directory
    — used internally by `mobile_static.py` (Stage 16) to scan a decompiled
    APK's smali/resources/assets tree for the same verified-secret
    detection this module already provides for git repos. Not part of
    `TrufflehogConfig`/the public `/api/repos/scans` surface: this is an
    internal step of the mobile scan pipeline, not something a user
    configures as its own source.
    """
    argv = ["trufflehog", "filesystem", path, "--json", "--only-verified", "--no-update"]
    try:
        returncode, stdout, stderr = await run_subprocess(argv)
    except FileNotFoundError as exc:
        raise TrufflehogRunError(
            "trufflehog binary not found — install it (see "
            "https://github.com/trufflesecurity/trufflehog#installation) and make sure it's "
            f"on PATH for the kiyooo server process: {exc}"
        ) from exc

    if returncode != 0 and not stdout.strip():
        raise TrufflehogRunError(
            f"trufflehog exited {returncode} with no output: "
            f"{stderr.decode(errors='replace')[-2000:]}"
        )
    return stdout


async def run_trufflehog(config: TrufflehogConfig) -> bytes:
    """Runs TruffleHog against one repo URL and returns its raw stdout.
    TruffleHog clones the repo itself (there is no separate clone step
    here) and writes JSON to stdout by default, same as Trivy.
    """
    argv = [
        "trufflehog",
        "git",
        _resolved_repo_url(config),
        "--json",
        "--only-verified",
        # A server-invoked scanner self-updating its own binary mid-run is
        # exactly the kind of unreviewed, unpinned change invariant #8
        # objects to for models — the same discipline applies to tooling:
        # a version bump should be a deliberate action, not a side effect
        # of running a scan. Also avoids a real failure mode: the binary
        # often isn't writable by the server process at all (caught live —
        # see this module's tests).
        "--no-update",
        *config.extra_args,
    ]
    try:
        returncode, stdout, stderr = await run_subprocess(argv)
    except FileNotFoundError as exc:
        raise TrufflehogRunError(
            "trufflehog binary not found — install it (see "
            "https://github.com/trufflesecurity/trufflehog#installation) and make sure it's "
            f"on PATH for the kiyooo server process: {exc}"
        ) from exc

    if returncode != 0 and not stdout.strip():
        raise TrufflehogRunError(
            f"trufflehog exited {returncode} with no output: "
            f"{stderr.decode(errors='replace')[-2000:]}"
        )
    return stdout


def sanitize_trufflehog_record(record: dict[str, Any]) -> dict[str, object]:
    """Every field the record actually carries, minus the ones that may
    hold a live secret. Keeps this adapter safe even if a future TruffleHog
    version adds a new field neither we nor TruffleHog's own docs
    anticipated as sensitive — an allowlist would be safer still, but this
    denylist matches TruffleHog's own documented guidance exactly, so a
    future field is only a gap if TruffleHog itself introduces one its own
    docs don't already warn about.

    Public (not `_`-prefixed): `mobile_static.py` (Stage 16) reuses this
    directly when building its own `ImportedFinding`s from the same
    TruffleHog record shape — the safety property belongs here, once, not
    re-implemented per caller.
    """
    return {k: v for k, v in record.items() if k not in _UNSAFE_FIELDS}


def parse_trufflehog_record(record: dict[str, Any]) -> ImportedFinding:
    git_meta: dict[str, Any] = {}
    source_metadata = record.get("SourceMetadata")
    if isinstance(source_metadata, dict):
        data = source_metadata.get("Data")
        if isinstance(data, dict):
            git = data.get("Git")
            if isinstance(git, dict):
                git_meta = git

    detector_name = str(record.get("DetectorName") or "unknown-detector")
    commit = str(git_meta.get("commit") or "unknown-commit")
    file_path = str(git_meta.get("file") or "unknown-file")
    line = git_meta.get("line")
    repository = str(git_meta.get("repository") or "unknown-repo")

    return ImportedFinding(
        external_id=f"{detector_name}:{commit}:{file_path}:{line}",
        vendor_issue_type=_VERIFIED_SECRET_ISSUE_TYPE,
        title=f"Verified {detector_name} credential in {file_path}",
        vendor_severity="critical",
        asset_type=AssetType.REPO,
        asset_value=repository,
        evidence_content={
            "detector_name": detector_name,
            "detector_description": record.get("DetectorDescription"),
            "verified": record.get("Verified"),
            "file": file_path,
            "line": line,
            "commit": commit,
            "repository": repository,
            "commit_author": git_meta.get("email"),
            "commit_timestamp": git_meta.get("timestamp"),
        },
        raw_payload=sanitize_trufflehog_record(record),
    )


def parse_trufflehog_records_raw(raw: bytes) -> list[dict[str, Any]]:
    """TruffleHog's `--json` output is newline-delimited (one finding
    object per line) in every version this was checked against — but
    falls back to parsing a single JSON array/object if stdout doesn't
    line-split into valid JSON, so a future format change degrades to
    "parses correctly" rather than "silently drops every finding."

    Public: `mobile_static.py` (Stage 16) calls this directly on
    `run_trufflehog_filesystem`'s output, then builds its own
    `ImportedFinding`s (different `asset_type`/`vendor_issue_type` than a
    git-sourced secret) from the same raw records this returns.
    """
    text = raw.decode(errors="replace").strip()
    if not text:
        return []

    lines = [line for line in text.splitlines() if line.strip()]
    if lines and all(_is_json_object_line(line) for line in lines):
        records = [json.loads(line) for line in lines]
    else:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]

    return [r for r in records if isinstance(r, dict)]


def parse_trufflehog_output(raw: bytes) -> list[ImportedFinding]:
    return [parse_trufflehog_record(r) for r in parse_trufflehog_records_raw(raw)]


def _is_json_object_line(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except json.JSONDecodeError:
        return False
