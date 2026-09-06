"""Manifest fixtures below are hand-written, valid AndroidManifest.xml
shapes (the real, documented Android manifest schema, not vendor-specific
guesswork) — there is no live apktool/jadx run or real APK in this sandbox,
same honest limitation the other adapters' tests document.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.mobile_static import (
    MobileScanConfig,
    MobileScanError,
    _hardcoded_secret_findings,
    find_firebase_urls,
    parse_manifest,
    run_mobile_static_scan,
)

_MANIFEST_WITH_ISSUES = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.acmecorp.app">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="24" />
    <application android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".SecretAdminActivity" android:exported="true" />
        <activity android:name=".SafeActivity" android:exported="true"
            android:permission="com.acmecorp.app.PRIVATE" />
        <service android:name=".SyncService">
            <intent-filter>
                <action android:name="com.acmecorp.SYNC" />
            </intent-filter>
        </service>
    </application>
</manifest>
"""

_MANIFEST_CLEAN = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.acmecorp.app">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />
    <application>
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>
"""


def test_parse_manifest_flags_exported_components_without_permission() -> None:
    findings = parse_manifest(_MANIFEST_WITH_ISSUES, "/apks/app.apk")
    exported = [
        f for f in findings if f.vendor_issue_type == "mobile-exported-component-no-permission"
    ]
    names = {f.evidence_content["component_name"] for f in exported}
    # MainActivity (explicit exported+intent-filter) and SecretAdminActivity
    # (explicit exported) both flagged; SafeActivity (has a permission) and
    # SyncService (implicitly exported via intent-filter, no permission) —
    # SyncService SHOULD also be flagged since it has no permission.
    assert ".MainActivity" in names
    assert ".SecretAdminActivity" in names
    assert ".SyncService" in names
    assert ".SafeActivity" not in names
    assert len(exported) == 3


def test_parse_manifest_detects_cleartext_traffic() -> None:
    findings = parse_manifest(_MANIFEST_WITH_ISSUES, "/apks/app.apk")
    cleartext = [f for f in findings if f.vendor_issue_type == "mobile-cleartext-traffic-allowed"]
    assert len(cleartext) == 1
    assert cleartext[0].asset_type == AssetType.MOBILE_APP


def test_parse_manifest_detects_outdated_target_sdk() -> None:
    findings = parse_manifest(_MANIFEST_WITH_ISSUES, "/apks/app.apk")
    outdated = [f for f in findings if f.vendor_issue_type == "mobile-outdated-target-sdk"]
    assert len(outdated) == 1
    assert outdated[0].evidence_content["target_sdk_version"] == 24


def test_parse_manifest_clean_app_produces_no_findings() -> None:
    findings = parse_manifest(_MANIFEST_CLEAN, "/apks/app.apk")
    assert findings == []


def test_find_firebase_urls_detects_embedded_database_url(tmp_path: Path) -> None:
    src_dir = tmp_path / "sources"
    src_dir.mkdir()
    (src_dir / "Config.smali").write_text(
        'const-string v0, "https://acmecorp-prod.firebaseio.com/"\n'
    )
    (src_dir / "Other.smali").write_text('const-string v0, "https://example.com/api"\n')

    findings = find_firebase_urls(tmp_path, "/apks/app.apk")
    assert len(findings) == 1
    assert findings[0].vendor_issue_type == "mobile-exposed-firebase-config"
    assert "acmecorp-prod.firebaseio.com" in findings[0].evidence_content["firebase_url"]


def test_find_firebase_urls_no_matches_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "Clean.smali").write_text('const-string v0, "https://example.com"\n')
    assert find_firebase_urls(tmp_path, "/apks/app.apk") == []


def test_hardcoded_secret_findings_maps_filesystem_trufflehog_record() -> None:
    record = {
        "DetectorName": "AWS",
        "DetectorDescription": "AWS access key",
        "Verified": True,
        "SourceMetadata": {"Data": {"Filesystem": {"file": "res/values/strings.xml", "line": 4}}},
        "Raw": "AKIAYVP4CIPPERUVIFXG",
        "Redacted": "AKIAYVP4CIPPERUVIFXG",
    }
    raw = json.dumps(record).encode()
    findings = _hardcoded_secret_findings(raw, "/apks/app.apk")
    assert len(findings) == 1
    f = findings[0]
    assert f.vendor_issue_type == "mobile-hardcoded-secret"
    assert f.asset_type == AssetType.MOBILE_APP
    assert f.evidence_content["file"] == "res/values/strings.xml"
    assert "AKIAYVP4CIPPERUVIFXG" not in json.dumps(f.raw_payload)
    assert "Raw" not in f.raw_payload
    assert "Redacted" not in f.raw_payload


async def test_run_mobile_static_scan_raises_when_apk_missing() -> None:
    with pytest.raises(MobileScanError, match="does not exist"):
        await run_mobile_static_scan(MobileScanConfig(apk_path="/nonexistent/app.apk"))


async def test_run_mobile_static_scan_raises_when_apktool_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_apk = tmp_path / "app.apk"
    fake_apk.write_bytes(b"fake apk content")

    async def fake_run_subprocess(
        argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr("kiyooo.ingest.adapters.mobile_static.run_subprocess", fake_run_subprocess)
    with pytest.raises(MobileScanError, match="apktool binary not found"):
        await run_mobile_static_scan(MobileScanConfig(apk_path=str(fake_apk)))
