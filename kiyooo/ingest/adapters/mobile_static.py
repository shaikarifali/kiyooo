"""Mobile static analysis — Android APK only in this
stage; IPA is deferred (different tooling, different plist-based manifest
shape — a real second effort, not a copy-paste of this one).

**Strictly static — this stage never opens a device, an emulator, or Frida.**
Dynamic instrumentation and intent-injection probing are active/intrusive
techniques for a separately-authorized offensive engagement, not a
passive-by-default self-scan tool (invariants #1, #3).

Wraps two existing OSS tools rather than reimplementing either (§0):
apktool (`iBotPeaches/Apktool`, Apache-2.0) decodes the manifest and
resources to plain text; TruffleHog's `filesystem` mode (already shipped
for Stage 15, `trufflehog.py`) scans the decoded tree — smali, resources,
assets — for verified live secrets, exactly the same detection this module
gives git repos. jadx (full Java decompilation) is a deliberate deferral:
apktool's smali/resource output already contains the string constants a
secret or endpoint grep needs; jadx would only make the *evidence* more
human-readable, not find anything apktool's output can't already surface.

The org supplies a local APK file path — there is no "fetch this app from
the Play Store" step here. Scraping an app store on the org's behalf,
without them having named and provided the file first, is out of scope.
"""

from __future__ import annotations

import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.trufflehog import (
    TrufflehogRunError,
    parse_trufflehog_records_raw,
    run_trufflehog_filesystem,
    sanitize_trufflehog_record,
)
from kiyooo.ingest.base import ImportedFinding
from kiyooo.recon.adapters._subprocess import run_subprocess

_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_EXPORTED_COMPONENT_TAGS = ("activity", "service", "receiver", "provider")
# Below this, a targetSdkVersion is treated as outdated. Android 11 (API 30)
# is Google Play's own minimum target-API floor as of the versions this was
# checked against — a defensible, documented default, not an arbitrary one.
# The actual value is always carried in evidence either way, so a reviewer
# (human or LLM) can apply a stricter or looser bar than this default.
_OUTDATED_TARGET_SDK_BELOW = 30
_FIREBASE_URL_PATTERN = re.compile(
    r"https://[a-z0-9-]+\.firebaseio\.com|"
    r"https://[a-z0-9-]+-default-rtdb\.[a-z0-9-]+\.firebasedatabase\.app"
)

MobilePlatform = Literal["android"]


class MobileScanError(RuntimeError):
    pass


class MobileScanConfig(BaseModel):
    platform: MobilePlatform = "android"
    apk_path: str = Field(min_length=1)


def _android_attr(element: ET.Element, name: str) -> str | None:
    return element.get(f"{{{_ANDROID_NS}}}{name}")


def _component_name(element: ET.Element) -> str:
    return _android_attr(element, "name") or "unknown-component"


def _is_effectively_exported(element: ET.Element) -> bool:
    exported = _android_attr(element, "exported")
    if exported is not None:
        return exported == "true"
    # No explicit `exported` attribute: implicitly exported (pre-API-31
    # behavior, and the safer assumption to flag on newer targets too) if
    # it declares an intent-filter.
    return element.find("intent-filter") is not None


def parse_manifest(xml_bytes: bytes, apk_path: str) -> list[ImportedFinding]:
    """apktool decodes `AndroidManifest.xml` to plain, readable XML (not
    binary AXML) — standard `xml.etree` parsing works directly on its
    output, no separate AXML decoder needed.
    """
    root = ET.fromstring(xml_bytes)
    findings: list[ImportedFinding] = []

    application = root.find("application")
    if application is not None:
        for tag in _EXPORTED_COMPONENT_TAGS:
            for component in application.findall(tag):
                permission = _android_attr(component, "permission")
                if permission:
                    continue
                if not _is_effectively_exported(component):
                    continue
                name = _component_name(component)
                findings.append(
                    ImportedFinding(
                        external_id=f"exported-component:{tag}:{name}",
                        vendor_issue_type="mobile-exported-component-no-permission",
                        title=f"Exported {tag} with no permission: {name}",
                        vendor_severity="medium",
                        asset_type=AssetType.MOBILE_APP,
                        asset_value=apk_path,
                        evidence_content={"component_type": tag, "component_name": name},
                        raw_payload={"component_type": tag, "component_name": name},
                    )
                )

        cleartext = _android_attr(application, "usesCleartextTraffic")
        if cleartext == "true":
            findings.append(
                ImportedFinding(
                    external_id="cleartext-traffic-allowed",
                    vendor_issue_type="mobile-cleartext-traffic-allowed",
                    title="App explicitly allows cleartext (unencrypted) network traffic",
                    vendor_severity="medium",
                    asset_type=AssetType.MOBILE_APP,
                    asset_value=apk_path,
                    evidence_content={"uses_cleartext_traffic": True},
                    raw_payload={"uses_cleartext_traffic": True},
                )
            )

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        target_sdk_raw = _android_attr(uses_sdk, "targetSdkVersion")
        if target_sdk_raw and target_sdk_raw.isdigit():
            target_sdk = int(target_sdk_raw)
            if target_sdk < _OUTDATED_TARGET_SDK_BELOW:
                findings.append(
                    ImportedFinding(
                        external_id="outdated-target-sdk",
                        vendor_issue_type="mobile-outdated-target-sdk",
                        title=(
                            f"targetSdkVersion {target_sdk} is below {_OUTDATED_TARGET_SDK_BELOW}"
                        ),
                        vendor_severity="low",
                        asset_type=AssetType.MOBILE_APP,
                        asset_value=apk_path,
                        evidence_content={"target_sdk_version": target_sdk},
                        raw_payload={"target_sdk_version": target_sdk},
                    )
                )

    return findings


def find_firebase_urls(decoded_dir: Path, apk_path: str) -> list[ImportedFinding]:
    """A Firebase Realtime Database URL embedded in an app is a static
    signal only — confirming it's actually unauthenticated would mean an
    active HTTP request to a third party's infrastructure, which this
    ingest adapter (invariant #1, #3: passive/static only) does not make.
    The finding is "this URL is embedded here," not "this database is
    open"; `verify/executor.py`'s scope-enforced active checks are the
    right place for that follow-up, not this module.
    """
    found: set[str] = set()
    for path in decoded_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for match in _FIREBASE_URL_PATTERN.finditer(text):
            found.add(match.group(0))

    return [
        ImportedFinding(
            external_id=f"firebase-config:{url}",
            vendor_issue_type="mobile-exposed-firebase-config",
            title=f"Firebase database URL embedded in app: {url}",
            vendor_severity="medium",
            asset_type=AssetType.MOBILE_APP,
            asset_value=apk_path,
            evidence_content={"firebase_url": url},
            raw_payload={"firebase_url": url},
        )
        for url in sorted(found)
    ]


async def _decode_apk(apk_path: str, output_dir: str) -> None:
    argv = ["apktool", "d", apk_path, "-o", output_dir, "-f"]
    try:
        returncode, _stdout, stderr = await run_subprocess(argv)
    except FileNotFoundError as exc:
        raise MobileScanError(
            "apktool binary not found — install it (see https://apktool.org/docs/install) "
            f"and make sure it's on PATH for the kiyooo server process: {exc}"
        ) from exc
    if returncode != 0:
        raise MobileScanError(
            f"apktool exited {returncode}: {stderr.decode(errors='replace')[-2000:]}"
        )


def _hardcoded_secret_findings(raw: bytes, apk_path: str) -> list[ImportedFinding]:
    findings: list[ImportedFinding] = []
    for record in parse_trufflehog_records_raw(raw):
        detector_name = str(record.get("DetectorName") or "unknown-detector")
        source_metadata = record.get("SourceMetadata") or {}
        data = source_metadata.get("Data") if isinstance(source_metadata, dict) else {}
        filesystem_meta = data.get("Filesystem") if isinstance(data, dict) else {}
        file_path = "unknown-file"
        if isinstance(filesystem_meta, dict):
            file_path = str(filesystem_meta.get("file") or file_path)

        findings.append(
            ImportedFinding(
                external_id=f"hardcoded-secret:{detector_name}:{file_path}",
                vendor_issue_type="mobile-hardcoded-secret",
                title=f"Verified {detector_name} credential hardcoded in app: {file_path}",
                vendor_severity="critical",
                asset_type=AssetType.MOBILE_APP,
                asset_value=apk_path,
                evidence_content={
                    "detector_name": detector_name,
                    "detector_description": record.get("DetectorDescription"),
                    "verified": record.get("Verified"),
                    "file": file_path,
                },
                raw_payload=sanitize_trufflehog_record(record),
            )
        )
    return findings


async def run_mobile_static_scan(config: MobileScanConfig) -> list[ImportedFinding]:
    """Orchestrates the full pipeline — unlike the single-tool adapters
    (Prowler/Trivy/TruffleHog), there's no one "raw output" blob to hand
    back for a separate parse step, so this returns findings directly.
    Each sub-step's own parser (`parse_manifest`, `find_firebase_urls`) is
    still independently pure/testable against a fixture.
    """
    if not Path(config.apk_path).is_file():  # noqa: ASYNC240 -- a single cheap stat(), not I/O worth a thread
        raise MobileScanError(f"apk_path does not exist or is not a file: {config.apk_path}")

    with tempfile.TemporaryDirectory(prefix="kiyooo-mobile-") as tmpdir:
        await _decode_apk(config.apk_path, tmpdir)
        decoded_dir = Path(tmpdir)

        findings: list[ImportedFinding] = []

        manifest_path = decoded_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            findings.extend(parse_manifest(manifest_path.read_bytes(), config.apk_path))

        findings.extend(find_firebase_urls(decoded_dir, config.apk_path))

        try:
            secret_scan_raw = await run_trufflehog_filesystem(tmpdir)
        except TrufflehogRunError as exc:
            raise MobileScanError(f"secret scan of decoded APK failed: {exc}") from exc
        findings.extend(_hardcoded_secret_findings(secret_scan_raw, config.apk_path))

        return findings
