"""Trivy — wraps aquasecurity/trivy (Apache-2.0,
~36.5k GitHub stars, the most-adopted OSS container/k8s scanner; one binary
covers image CVEs, secrets, and Kubernetes misconfiguration) rather than
reimplementing any of that ourselves (§0's non-goal, same as every other
stage).

Two scan kinds share one parser because Trivy emits the same `Results[]`
shape (`Target`/`Class`/`Type` + `Vulnerabilities[]`/`Misconfigurations[]`)
for both `trivy image` and `trivy k8s` — k8s mode just wraps that same
shape one level deeper, grouped per cluster resource
(`{"Vulnerabilities": [{"Namespace","Kind","Name","Results": [...]}], ...}`
at the top level instead of a bare `Results[]`).

Only `Status == "FAIL"` misconfigurations become candidate findings (a PASS
is not evidence of anything — same rule Prowler's adapter applies).
Vulnerabilities have no pass/fail status; every reported one is a candidate,
same as any CVE-matching detector.

CVE findings are deliberately NOT mapped to a category per-CVE — that
doesn't scale through a hand-maintained `vendor_mapping.yaml` the way
Prowler's small, fixed check-id set does. Every CVE finding uses the same
constant `vendor_issue_type` ("trivy-vulnerable-package"), landing in one
`vulnerable-base-image` category; the specific CVE ID, package, and fixed
version are carried as evidence for Stage 5's LLM adjudicator to reason
about, not encoded in our own category granularity. Misconfiguration checks
ARE a small, fixed, Prowler-like rule set, so those map one check-id per
category, same as Prowler.
"""

from __future__ import annotations

import json
import os
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding
from kiyooo.llm.credentials import resolve_credential
from kiyooo.recon.adapters._subprocess import run_subprocess

TrivyScanKind = Literal["image", "k8s"]

_SHELL_METACHARACTERS = (";", "|", "&", "$(", "`", "\n")
_VULNERABLE_PACKAGE_ISSUE_TYPE = "trivy-vulnerable-package"


class TrivyRunError(RuntimeError):
    pass


class TrivyConfig(BaseModel):
    """`scan_kind="image"`: `target` is an image reference (`nginx:1.25`).
    `scan_kind="k8s"`: `target` is a kubeconfig context name, or `""` for
    the current context — the whole cluster is scanned either way (Trivy
    has no single-namespace-only mode used here).

    `credential_env` and `extra_args` are the same free-form escape hatches
    as `ProwlerConfig` — a k8s scan typically sets `KUBECONFIG` to a path
    the kiyooo server can read (the credential_ref points at an env var
    holding that path, never kubeconfig content itself), an image scan
    against a private registry sets whatever that registry's Docker/OCI
    client expects (`DOCKER_CONFIG`, registry-specific token vars, ...).
    """

    scan_kind: TrivyScanKind
    target: str = ""
    credential_env: dict[str, str] = Field(default_factory=dict)
    extra_args: list[str] = Field(default_factory=list)

    @field_validator("extra_args")
    @classmethod
    def _no_shell_metacharacters(cls, value: list[str]) -> list[str]:
        for arg in value:
            if any(ch in arg for ch in _SHELL_METACHARACTERS):
                raise ValueError(f"extra_arg {arg!r} contains a shell metacharacter")
        return value


def _resolve_env(config: TrivyConfig) -> dict[str, str]:
    env = dict(os.environ)
    for env_var, ref in config.credential_env.items():
        value = resolve_credential(ref)
        if value is not None:
            env[env_var] = value
    return env


async def run_trivy(config: TrivyConfig) -> bytes:
    """Runs Trivy and returns its raw stdout JSON. Unlike Prowler, Trivy
    writes JSON to stdout by default when no `--output` flag is given, so
    there's no scratch file/directory to manage here.
    """
    if config.scan_kind == "image":
        if not config.target.strip():
            raise TrivyRunError("scan_kind 'image' requires a non-empty target (image reference)")
        argv = ["trivy", "image", "--format", "json", *config.extra_args, config.target]
    else:
        argv = ["trivy", "k8s", "--report", "all", "--format", "json"]
        if config.target.strip():
            argv += ["--context", config.target]
        argv += [*config.extra_args, "cluster"]

    env = _resolve_env(config)
    try:
        returncode, stdout, stderr = await run_subprocess(argv, env=env)
    except FileNotFoundError as exc:
        raise TrivyRunError(
            "trivy binary not found — install it (see "
            "https://github.com/aquasecurity/trivy#installation) and make sure it's on PATH "
            f"for the kiyooo server process: {exc}"
        ) from exc

    if not stdout.strip():
        raise TrivyRunError(
            f"trivy exited {returncode} and produced no output on stdout: "
            f"{stderr.decode(errors='replace')[-2000:]}"
        )
    return stdout


def _severity_label(raw: object) -> str:
    return str(raw or "UNKNOWN")


def _iter_result_blocks(data: dict[str, object]) -> list[tuple[dict[str, object], dict[str, str]]]:
    """Yields `(result_dict, k8s_context)` pairs. `k8s_context` is `{}` for
    plain `trivy image` output (a bare top-level `Results[]`), or
    `{"namespace", "kind", "name"}` per entry for `trivy k8s` output, which
    nests the same `Results[]` shape one level under per-resource
    `Vulnerabilities`/`Misconfigurations` arrays instead.
    """
    blocks: list[tuple[dict[str, object], dict[str, str]]] = []

    top_results = data.get("Results")
    if isinstance(top_results, list):
        for result in top_results:
            if isinstance(result, dict):
                blocks.append((result, {}))
        return blocks

    for top_key in ("Vulnerabilities", "Misconfigurations"):
        entries = data.get(top_key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            context = {
                "namespace": str(entry.get("Namespace") or ""),
                "kind": str(entry.get("Kind") or ""),
                "name": str(entry.get("Name") or ""),
            }
            nested_results = entry.get("Results")
            if isinstance(nested_results, list):
                for result in nested_results:
                    if isinstance(result, dict):
                        blocks.append((result, context))
    return blocks


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _workload_asset_value(context: dict[str, str], target: str) -> str:
    if context.get("name"):
        return f"{context.get('namespace', '')}/{context.get('kind', '')}/{context['name']}"
    return target


def _parse_vulnerabilities(
    result: dict[str, object], context: dict[str, str], artifact_name: str
) -> list[ImportedFinding]:
    target = str(result.get("Target") or artifact_name)
    asset_type = AssetType.K8S_WORKLOAD if context else AssetType.CONTAINER_IMAGE
    asset_value = _workload_asset_value(context, artifact_name or target)

    findings: list[ImportedFinding] = []
    for vuln in _as_list(result.get("Vulnerabilities")):
        if not isinstance(vuln, dict):
            continue
        cve_id = str(vuln.get("VulnerabilityID") or "unknown-cve")
        pkg_name = str(vuln.get("PkgName") or "unknown-package")
        findings.append(
            ImportedFinding(
                external_id=f"{cve_id}:{pkg_name}:{asset_value}",
                vendor_issue_type=_VULNERABLE_PACKAGE_ISSUE_TYPE,
                title=f"{cve_id}: {pkg_name} {vuln.get('InstalledVersion') or ''}".strip(),
                vendor_severity=_severity_label(vuln.get("Severity")),
                asset_type=asset_type,
                asset_value=asset_value,
                evidence_content={
                    "cve_id": cve_id,
                    "package": pkg_name,
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "target": target,
                    "k8s_resource": context or None,
                    "title": vuln.get("Title"),
                    "primary_url": vuln.get("PrimaryURL"),
                },
                raw_payload=vuln,
            )
        )
    return findings


def _parse_misconfigurations(
    result: dict[str, object], context: dict[str, str], artifact_name: str
) -> list[ImportedFinding]:
    target = str(result.get("Target") or artifact_name)
    asset_type = AssetType.K8S_WORKLOAD if context else AssetType.CONTAINER_IMAGE
    asset_value = _workload_asset_value(context, artifact_name or target)

    findings: list[ImportedFinding] = []
    for misconf in _as_list(result.get("Misconfigurations")):
        if not isinstance(misconf, dict):
            continue
        if misconf.get("Status") != "FAIL":
            continue
        check_id = str(misconf.get("ID") or misconf.get("AVDID") or "unknown-check")
        findings.append(
            ImportedFinding(
                external_id=f"{check_id}:{asset_value}",
                vendor_issue_type=check_id,
                title=str(misconf.get("Title") or check_id),
                vendor_severity=_severity_label(misconf.get("Severity")),
                asset_type=asset_type,
                asset_value=asset_value,
                evidence_content={
                    "check_id": check_id,
                    "message": misconf.get("Message"),
                    "resolution": misconf.get("Resolution"),
                    "target": target,
                    "k8s_resource": context or None,
                },
                raw_payload=misconf,
            )
        )
    return findings


def parse_trivy_output(raw: bytes) -> list[ImportedFinding]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        return []

    artifact_name = str(data.get("ArtifactName") or data.get("ClusterName") or "")
    findings: list[ImportedFinding] = []
    for result, context in _iter_result_blocks(data):
        findings.extend(_parse_vulnerabilities(result, context, artifact_name))
        findings.extend(_parse_misconfigurations(result, context, artifact_name))
    return findings
