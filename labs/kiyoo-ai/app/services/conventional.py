"""The non-AI half of the lab — plumbing and contrast, not
the main point. Three of these matter more than the rest: `portal` (SSO
false-positive), `shop` (WAF-reduced, not suppressed), `legacy`
(expired-cert, correctly low/not-exploitable) — these prove triage is
doing work, not just detecting.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from ..common import LAB_NOTICE, decoy_headers, host

# --- landing -----------------------------------------------------------

landing_app = FastAPI(title="kiyoo-ai lab landing", docs_url=None, redoc_url=None)


@landing_app.get("/", response_class=HTMLResponse)
async def landing() -> str:
    return (
        f"<h1>kiyoo-ai lab</h1><p>{LAB_NOTICE}</p>"
        f"<p>Part of the <a href='https://github.com/'>kiyooo</a> project. "
        f"See <code>the design doc</code> in this lab's repo for the full asset "
        f"inventory and expected findings.</p>"
    )


@landing_app.get("/security.txt")
@landing_app.get("/.well-known/security.txt")
async def security_txt() -> PlainTextResponse:
    return PlainTextResponse(
        "Contact: https://github.com/\n"
        "Policy: This is a deliberately vulnerable research lab. "
        "Everything here is synthetic and intentionally exposed.\n"
    )


@landing_app.get("/robots.txt")
async def robots_txt() -> PlainTextResponse:
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@landing_app.get("/_lab/notice", response_class=PlainTextResponse)
async def lab_notice() -> str:
    return LAB_NOTICE


# --- staging (nonprod-to-internet, downgraded via seeded-data detection) --

staging_app = FastAPI(title="staging (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@staging_app.get("/", response_class=HTMLResponse)
async def staging_root() -> HTMLResponse:
    return HTMLResponse(
        f"<h1>[STAGING] acmecorp admin</h1><p>{LAB_NOTICE}</p>"
        "<p>debug=true build=lab-staging-0001</p>",
        headers=decoy_headers({"x-debug-mode": "true"}),
    )


# --- admin login (unauth'd; contrast case for `portal`, below) ---------

admin_app = FastAPI(title="admin (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@admin_app.get("/", response_class=HTMLResponse)
async def admin_root() -> str:
    return (
        "<h1>Admin login</h1><form><input name='user'/><input name='pw'/></form>"
        f"<p>{LAB_NOTICE}</p>"
    )


# --- portal (behind SSO -> correct false-positive) + sso mock ----------

portal_app = FastAPI(title="portal (kiyoo-ai lab)", docs_url=None, redoc_url=None)
sso_app = FastAPI(title="sso (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@portal_app.get("/")
async def portal_root() -> RedirectResponse:
    return RedirectResponse(url=f"https://{host('sso')}/login?redirect=portal", status_code=302)


@sso_app.get("/", response_class=HTMLResponse)
async def sso_root() -> str:
    return f"<h1>Corp SSO</h1><p>{LAB_NOTICE}</p><p>Try /login.</p>"


@sso_app.get("/login", response_class=HTMLResponse)
async def sso_login() -> str:
    return f"<h1>Corp SSO</h1><p>Sign in to continue.</p><p>{LAB_NOTICE}</p>"


# --- api (synthetic data -> severity downgrade signal) -----------------

api_app = FastAPI(title="api (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@api_app.get("/", response_class=HTMLResponse)
async def api_root() -> str:
    return f"<h1>api</h1><p>{LAB_NOTICE}</p><p>Try /v1/users.</p>"


@api_app.get("/v1/users")
async def api_users() -> JSONResponse:
    return JSONResponse(
        [
            {"id": 1, "name": "Jane Faker", "email": "jane.faker@example.com"},
            {"id": 2, "name": "John Faker", "email": "john.faker@example.com"},
        ],
        headers=decoy_headers(),
    )


# --- git (exposed .env / .git/config, incl. a lab-fake AI key) ---------

git_app = FastAPI(title="git (kiyoo-ai lab)", docs_url=None, redoc_url=None)

_FAKE_ANTHROPIC_KEY = "sk-ant-api03-LABFAKE00000000000000000000000000000000000000AA"
_FAKE_OPENAI_KEY = "sk-LABFAKE000000000000000000000000000000000000"


@git_app.get("/", response_class=HTMLResponse)
async def git_root() -> str:
    return f"<h1>git</h1><p>{LAB_NOTICE}</p><p>Try /.env and /.git/config.</p>"


@git_app.get("/.env", response_class=PlainTextResponse)
async def dotenv() -> str:
    return (
        f"# {LAB_NOTICE}\n"
        f"ANTHROPIC_API_KEY={_FAKE_ANTHROPIC_KEY}\n"
        f"OPENAI_API_KEY={_FAKE_OPENAI_KEY}\n"
        "DATABASE_URL=postgres://labfake:labfake@localhost/labfake\n"
    )


@git_app.get("/.git/config", response_class=PlainTextResponse)
async def git_config() -> str:
    return f'# {LAB_NOTICE}\n[remote "origin"]\n\turl = https://git.example/acmecorp/internal.git\n'


# --- files (S3-style open bucket listing) -------------------------------

files_app = FastAPI(title="files (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@files_app.get("/", response_class=PlainTextResponse)
async def files_listing() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<ListBucketResult><Name>acmecorp-files-lab</Name>"
        "<Contents><Key>invoices-2026-q1.pdf</Key><Size>18211</Size></Contents>"
        f"</ListBucketResult>\n<!-- {LAB_NOTICE} -->"
    )


# --- shop (behind a WAF-shaped header, vulnerable banner underneath) ---

shop_app = FastAPI(title="shop (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@shop_app.get("/", response_class=HTMLResponse)
async def shop_root() -> HTMLResponse:
    return HTMLResponse(
        f"<h1>acmecorp shop</h1><p>{LAB_NOTICE}</p>",
        headers=decoy_headers({"server": "Apache/2.4.49", "cf-ray": "labfake0000000-lab"}),
    )


# --- legacy (expired cert is handled at the reverse-proxy/TLS layer —
# this app only needs to serve the static "moved" page with no forms) --

legacy_app = FastAPI(title="legacy (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@legacy_app.get("/", response_class=HTMLResponse)
async def legacy_root() -> str:
    return f"<h1>This site has moved.</h1><p>{LAB_NOTICE}</p>"


# --- noise hosts (nNNN.<domain> — healthy, zero findings expected) -----


def build_noise_app(name: str) -> FastAPI:
    noise_app = FastAPI(title=f"{name} (kiyoo-ai lab, noise)", docs_url=None, redoc_url=None)

    @noise_app.get("/", response_class=PlainTextResponse)
    async def noise_root() -> str:  # noqa: ANN202 - closure, fine for a lab factory
        return f"ok — {name}, nothing to see here"

    return noise_app


NOISE_HOST_COUNT = 10  # 100 in the design's public deployment; 10 is enough locally
