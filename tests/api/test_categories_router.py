"""`/api/categories` and its preview endpoint touch org_context only —
never the database — so unlike most routers these are fully testable via
TestClient without a live Postgres. `preview_category` reuses
`detect/evaluate.py`'s real `evaluate_block`, the same function
`kiyooo categories test` and live detection call.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from kiyooo.api.app import create_app
from kiyooo.config import Settings


def _client() -> TestClient:
    return TestClient(create_app(Settings()))


def test_list_categories_returns_org_context_example_categories() -> None:
    with _client() as client:
        resp = client.get("/api/categories")
    assert resp.status_code == 200
    body = resp.json()
    ids = {c["id"] for c in body}
    assert "exposed-database" in ids
    assert len(body) == 40


def test_preview_unknown_category_is_404() -> None:
    with _client() as client:
        resp = client.post(
            "/api/categories/does-not-exist/preview",
            json={"asset": {"type": "tcp_service", "value": "10.0.0.5:3306"}, "evidence": []},
        )
    assert resp.status_code == 404


def test_preview_matching_asset_and_evidence() -> None:
    with _client() as client:
        resp = client.post(
            "/api/categories/exposed-database/preview",
            json={
                "asset": {"type": "tcp_service", "value": "10.0.0.5:3306"},
                "evidence": [{"kind": "port_banner", "content": {"port": 3306}}],
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["matched"] is True
    assert body["evidence_ids"] == ["ev_case_0"]


def test_preview_non_matching_asset_and_evidence() -> None:
    with _client() as client:
        resp = client.post(
            "/api/categories/exposed-database/preview",
            json={
                "asset": {"type": "tcp_service", "value": "10.0.0.5:22"},
                "evidence": [{"kind": "port_banner", "content": {"port": 22}}],
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["matched"] is False
    assert body["evidence_ids"] == []
