"""kiyoo-ai lab — a single ASGI app, routed by `Host` header (the design
recommends exactly this: "one app with Host-based routing... simpler and
resets faster" than one container per service). Every hostname below maps
to one decoy module under `services/`; see the design for the DNS layout
this mirrors.

Run locally:  uvicorn app.main:app --host 0.0.0.0 --port 8000
Then curl with an explicit Host header, or point /etc/hosts at 127.0.0.1
for each `*.kiyoo-ai.lab` name (see ../README.md).

KIYOO_LAB_DOMAIN controls the domain suffix (default `kiyoo-ai.lab`, so
this never collides with a real hostname); the public deployment sets it
to the real lab domain.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.routing import BaseRoute, Host, Mount

from .common import host
from .services import (
    ai_portal,
    chat,
    conventional,
    internal_tools,
    llm,
    mcp_docs,
    mcp_legacy,
    mcp_ops,
    mlflow,
    models_listing,
    notebook,
    qdrant,
    vectors,
)

routes: list[BaseRoute] = [
    # --- AI surface, the headline ---
    Host(host("mcp-docs"), app=mcp_docs.app),
    Host(host("mcp-ops"), app=mcp_ops.app),
    Host(host("mcp-legacy"), app=mcp_legacy.app),
    Host(host("llm"), app=llm.app),
    Host(host("chat"), app=chat.app),
    Host(host("vectors"), app=vectors.app),
    Host(host("qdrant"), app=qdrant.app),
    Host(host("mlflow"), app=mlflow.app),
    Host(host("notebook"), app=notebook.app),
    Host(host("models"), app=models_listing.app),
    Host(host("ai-portal"), app=ai_portal.app),
    Host(host("internal-tools"), app=internal_tools.app),
    # --- conventional surface ---
    Host(host("staging"), app=conventional.staging_app),
    Host(host("admin"), app=conventional.admin_app),
    Host(host("portal"), app=conventional.portal_app),
    Host(host("sso"), app=conventional.sso_app),
    Host(host("api"), app=conventional.api_app),
    Host(host("git"), app=conventional.git_app),
    Host(host("files"), app=conventional.files_app),
    Host(host("shop"), app=conventional.shop_app),
    Host(host("legacy"), app=conventional.legacy_app),
]

# n001..n0NN.<domain> — plain healthy hosts, the noise floor.
for _i in range(1, conventional.NOISE_HOST_COUNT + 1):
    _name = f"n{_i:03d}"
    routes.append(Host(host(_name), app=conventional.build_noise_app(_name)))

# Anything not otherwise matched (bare domain, unknown Host header) falls
# through to the lab landing page — this route has no Host() wrapper, so
# it only gets reached once every specific match above has failed.
routes.append(Mount("/", app=conventional.landing_app))

app = Starlette(routes=routes)
