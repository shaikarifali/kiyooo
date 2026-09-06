"""Parser tests use hand-constructed samples matching Trivy's publicly
documented JSON schema (`pkg/types` — DetectedVulnerability/
DetectedMisconfiguration field names, and the `trivy k8s` top-level
`Vulnerabilities`/`Misconfigurations` grouping) — there is no live Trivy
binary, container image, or Kubernetes cluster in this sandbox to record a
real run against, same honest limitation Prowler's tests document.
"""

from __future__ import annotations

import json

import pytest

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.trivy import (
    TrivyConfig,
    TrivyRunError,
    parse_trivy_output,
    run_trivy,
)

_IMAGE_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "registry.acmecorp.example/web-app:1.4.2",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "web-app:1.4.2 (debian 12.5)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11-1",
                    "FixedVersion": "3.0.13-1",
                    "Severity": "CRITICAL",
                    "Title": "openssl: buffer overflow",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1234",
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "AVD-DS-0002",
                    "AVDID": "AVD-DS-0002",
                    "Title": "Image user should not be 'root'",
                    "Message": "Specify at least 1 USER command in Dockerfile",
                    "Severity": "HIGH",
                    "Status": "FAIL",
                    "Resolution": "Add 'USER <non-root user>' line to the Dockerfile",
                },
                {
                    "ID": "AVD-DS-0026",
                    "Title": "No HEALTHCHECK defined",
                    "Message": "Add HEALTHCHECK instruction",
                    "Severity": "LOW",
                    "Status": "PASS",
                },
            ],
        },
    ],
}

_K8S_REPORT = {
    "ClusterName": "prod-cluster",
    "Vulnerabilities": [
        {
            "Namespace": "default",
            "Kind": "Deployment",
            "Name": "web-app",
            "Results": [
                {
                    "Target": "web-app (debian 12.5)",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-5678",
                            "PkgName": "libc6",
                            "InstalledVersion": "2.36-9",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        }
    ],
    "Misconfigurations": [
        {
            "Namespace": "default",
            "Kind": "Pod",
            "Name": "web-app-7c8f9",
            "Results": [
                {
                    "Target": "Pod/web-app-7c8f9",
                    "Class": "config",
                    "Type": "kubernetes",
                    "Misconfigurations": [
                        {
                            "ID": "AVD-KSV-0011",
                            "Title": "Container should not be privileged",
                            "Message": "Container 'app' of Pod 'web-app-7c8f9' should set "
                            "'securityContext.privileged' to false",
                            "Severity": "CRITICAL",
                            "Status": "FAIL",
                            "Resolution": "Set 'containers[].securityContext.privileged' to false",
                        }
                    ],
                }
            ],
        }
    ],
}


def test_parse_trivy_output_image_mode_extracts_vulnerability() -> None:
    findings = parse_trivy_output(json.dumps(_IMAGE_REPORT).encode())
    vuln_findings = [f for f in findings if f.vendor_issue_type == "trivy-vulnerable-package"]
    assert len(vuln_findings) == 1
    f = vuln_findings[0]
    assert f.asset_type == AssetType.CONTAINER_IMAGE
    assert f.asset_value == "registry.acmecorp.example/web-app:1.4.2"
    assert f.title == "CVE-2024-1234: openssl 3.0.11-1"
    assert f.vendor_severity == "CRITICAL"
    assert f.evidence_content["fixed_version"] == "3.0.13-1"


def test_parse_trivy_output_image_mode_only_includes_failed_misconfigs() -> None:
    findings = parse_trivy_output(json.dumps(_IMAGE_REPORT).encode())
    misconf_findings = [f for f in findings if f.vendor_issue_type.startswith("AVD-DS")]
    assert len(misconf_findings) == 1
    assert misconf_findings[0].vendor_issue_type == "AVD-DS-0002"
    assert misconf_findings[0].vendor_severity == "HIGH"


def test_parse_trivy_output_k8s_mode_extracts_workload_vulnerability() -> None:
    findings = parse_trivy_output(json.dumps(_K8S_REPORT).encode())
    vuln_findings = [f for f in findings if f.vendor_issue_type == "trivy-vulnerable-package"]
    assert len(vuln_findings) == 1
    f = vuln_findings[0]
    assert f.asset_type == AssetType.K8S_WORKLOAD
    assert f.asset_value == "default/Deployment/web-app"
    assert f.evidence_content["cve_id"] == "CVE-2024-5678"


def test_parse_trivy_output_k8s_mode_extracts_privileged_container_misconfig() -> None:
    findings = parse_trivy_output(json.dumps(_K8S_REPORT).encode())
    misconf_findings = [f for f in findings if f.vendor_issue_type == "AVD-KSV-0011"]
    assert len(misconf_findings) == 1
    f = misconf_findings[0]
    assert f.asset_type == AssetType.K8S_WORKLOAD
    assert f.asset_value == "default/Pod/web-app-7c8f9"
    assert f.vendor_severity == "CRITICAL"


def test_parse_trivy_output_total_finding_count() -> None:
    image_findings = parse_trivy_output(json.dumps(_IMAGE_REPORT).encode())
    k8s_findings = parse_trivy_output(json.dumps(_K8S_REPORT).encode())
    # 1 vuln + 1 failed misconfig (the PASS one is excluded) per report.
    assert len(image_findings) == 2
    assert len(k8s_findings) == 2


def test_config_rejects_shell_metacharacters_in_extra_args() -> None:
    with pytest.raises(ValueError, match="shell metacharacter"):
        TrivyConfig(scan_kind="image", target="nginx:1.25", extra_args=["--severity; rm -rf /"])


async def test_run_trivy_image_requires_a_target() -> None:
    with pytest.raises(TrivyRunError, match="requires a non-empty target"):
        await run_trivy(TrivyConfig(scan_kind="image", target=""))


async def test_run_trivy_raises_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr("kiyooo.ingest.adapters.trivy.run_subprocess", fake_run_subprocess)
    with pytest.raises(TrivyRunError, match="trivy binary not found"):
        await run_trivy(TrivyConfig(scan_kind="image", target="nginx:1.25"))


async def test_run_trivy_raises_on_empty_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        return 1, b"", b"FATAL: image not found"

    monkeypatch.setattr("kiyooo.ingest.adapters.trivy.run_subprocess", fake_run_subprocess)
    with pytest.raises(TrivyRunError, match="image not found"):
        await run_trivy(TrivyConfig(scan_kind="image", target="nginx:1.25"))


async def test_run_trivy_k8s_builds_expected_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_argv: list[str] = []

    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        seen_argv.extend(argv)
        return 0, b"{}", b""

    monkeypatch.setattr("kiyooo.ingest.adapters.trivy.run_subprocess", fake_run_subprocess)
    await run_trivy(TrivyConfig(scan_kind="k8s", target="prod-context"))
    assert seen_argv == [
        "trivy",
        "k8s",
        "--report",
        "all",
        "--format",
        "json",
        "--context",
        "prod-context",
        "cluster",
    ]
