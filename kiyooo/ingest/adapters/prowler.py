"""Prowler — wraps prowler-cloud/prowler (Apache-2.0,
~14k GitHub stars, the most widely used OSS cloud security scanner; one
binary covers AWS, Azure, GCP, and Kubernetes) rather than reimplementing
cloud posture checks ourselves — same non-goal as every other stage (§0:
"we orchestrate nuclei/others, we don't replace them").

Prowler audits an account using credentials the org itself supplies against
that cloud's own control-plane API — this is the same "enrichment, not a
probe against infrastructure we don't operate" reasoning `enrich/cloud_aws.py`
(Stage 3) already documents, so this module does not go through `ScopeGuard`:
there is no third-party target here to bound contact with, only the org's
own account, authenticated as the org.

Parses Prowler's JSON-OCSF output (OCSF Detection Finding v1.1.0 — Prowler's
default/recommended format since v4; the older native `.json` format is
deprecated upstream). Only `status_code == "FAIL"` records become candidate
findings: a passed check is not evidence of anything, and turning it into a
row would be exactly the noise this project exists to remove.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding
from kiyooo.llm.credentials import resolve_credential
from kiyooo.recon.adapters._subprocess import run_subprocess

CloudProvider = Literal["aws", "azure", "gcp", "kubernetes"]

_SHELL_METACHARACTERS = (";", "|", "&", "$(", "`", "\n")


class ProwlerRunError(RuntimeError):
    pass


class ProwlerConfig(BaseModel):
    """What one entry in `org-context.example/cloud_accounts.yaml` supplies.

    `credential_env` is deliberately a free-form `{ENV_VAR: credential_ref}`
    map rather than typed AWS/Azure/GCP-specific fields: each cloud's SDK
    (and Prowler itself) already reads its own standard env vars
    (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`,
    `GOOGLE_APPLICATION_CREDENTIALS`, ...) — modeling every one of those as a
    bespoke field would drift from Prowler's own docs immediately and still
    wouldn't cover every auth mode. The org supplies whichever env vars their
    setup needs; every value is a `credential_ref` (invariant #6/#7), never a
    raw secret in this config.

    `extra_args` is the same kind of escape hatch for whatever CLI flag a
    given account's auth mode needs (`--profile`, `--role-arn`,
    `--subscription-ids`, `--project-ids`, ...) that isn't a credential at
    all — configuration, not code, is how one org's cloud footprint differs
    from another's.
    """

    provider: CloudProvider
    credential_env: dict[str, str] = Field(default_factory=dict)
    extra_args: list[str] = Field(default_factory=list)

    @field_validator("extra_args")
    @classmethod
    def _no_shell_metacharacters(cls, value: list[str]) -> list[str]:
        # These become an argv list, never a shell string — but reject an
        # operator trying to smuggle a second command through one arg anyway.
        for arg in value:
            if any(ch in arg for ch in _SHELL_METACHARACTERS):
                raise ValueError(f"extra_arg {arg!r} contains a shell metacharacter")
        return value


def _resolve_env(config: ProwlerConfig) -> dict[str, str]:
    env = dict(os.environ)
    for env_var, ref in config.credential_env.items():
        value = resolve_credential(ref)
        if value is not None:
            env[env_var] = value
    return env


async def run_prowler(config: ProwlerConfig) -> bytes:
    """Runs Prowler against one configured account and returns its raw
    JSON-OCSF report bytes. Prowler writes reports to a file (there is no
    stdout-only mode), so this uses a scratch directory that's always
    cleaned up, win or lose.
    """
    env = _resolve_env(config)
    with tempfile.TemporaryDirectory(prefix="kiyooo-prowler-") as tmpdir:
        argv = [
            "prowler",
            config.provider,
            "-M",
            "json-ocsf",
            "-o",
            tmpdir,
            "-F",
            "report",
            "--no-banner",
            *config.extra_args,
        ]
        try:
            returncode, _stdout, stderr = await run_subprocess(argv, env=env)
        except FileNotFoundError as exc:
            # The `prowler` binary itself isn't installed/on PATH — an
            # expected, common failure mode (this environment has no
            # scanners installed at all), not a code bug. Surface it the
            # same clean way a non-zero exit does, not as an unhandled 500.
            raise ProwlerRunError(
                "prowler binary not found — install it (pipx install prowler or "
                "see https://github.com/prowler-cloud/prowler) and make sure it's on PATH "
                f"for the kiyooo server process: {exc}"
            ) from exc
        report_path = Path(tmpdir) / "report.ocsf.json"
        if not report_path.exists():
            raise ProwlerRunError(
                f"prowler exited {returncode} and produced no report at "
                f"{report_path.name}: {stderr.decode(errors='replace')[-2000:]}"
            )
        return report_path.read_bytes()


def _as_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def parse_ocsf_finding(record: dict[str, object]) -> ImportedFinding | None:
    """One OCSF Detection Finding [2004] record -> `ImportedFinding`, or
    `None` for anything that isn't a failed check (PASS/MANUAL/INFO records
    exist in the same report and are not candidate findings).
    """
    if record.get("status_code") != "FAIL":
        return None

    metadata = _as_dict(record.get("metadata"))
    finding_info = _as_dict(record.get("finding_info"))
    cloud = _as_dict(record.get("cloud"))
    account = _as_dict(cloud.get("account"))
    resources = _as_list(record.get("resources"))
    resource = _as_dict(resources[0]) if resources else {}
    remediation = _as_dict(record.get("remediation"))

    check_id = str(metadata.get("event_code") or finding_info.get("uid") or "unknown-check")
    resource_uid = str(resource.get("uid") or resource.get("name") or "unknown-resource")
    account_uid = str(account.get("uid") or "unknown-account")
    title = str(finding_info.get("title") or record.get("message") or check_id)

    return ImportedFinding(
        external_id=f"{check_id}:{resource_uid}",
        vendor_issue_type=check_id,
        title=title,
        vendor_severity=str(record.get("severity") or "unknown"),
        asset_type=AssetType.CLOUD_RESOURCE,
        asset_value=resource_uid,
        evidence_content={
            "check_id": check_id,
            "status_detail": record.get("status_detail") or record.get("message"),
            "resource_type": resource.get("type"),
            "region": resource.get("region") or cloud.get("region"),
            "account_id": account_uid,
            "provider": cloud.get("provider"),
            "description": finding_info.get("desc"),
            "remediation": remediation.get("desc"),
        },
        raw_payload=record,
    )


def parse_prowler_output(raw: bytes) -> list[ImportedFinding]:
    data = json.loads(raw)
    records = data if isinstance(data, list) else [data]
    findings: list[ImportedFinding] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        parsed = parse_ocsf_finding(record)
        if parsed is not None:
            findings.append(parsed)
    return findings
