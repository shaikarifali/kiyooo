"""One route whose error path is reachable without a live database:
`query_assets` raises `QueryError` while parsing a malformed clause,
before it ever calls `session.execute` — so `get_session`'s lazy
(unconnected-until-used) session never actually needs Postgres for this
specific request. See `tests/api/test_app.py`'s docstring for why the
happy paths aren't tested the same way.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from kiyooo.api.app import create_app
from kiyooo.config import Settings


def test_malformed_query_clause_returns_400_without_touching_the_database() -> None:
    app = create_app(Settings())
    with TestClient(app) as client:
        resp = client.get("/api/assets", params={"q": "unsupported_field=x"})
    assert resp.status_code == 400
    assert "unsupported_field" in resp.json()["detail"]


def test_unknown_asset_type_in_clause_returns_400() -> None:
    app = create_app(Settings())
    with TestClient(app) as client:
        resp = client.get("/api/assets", params={"q": "type=not-a-real-type"})
    assert resp.status_code == 400
