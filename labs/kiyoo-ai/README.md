# kiyoo-ai — the AI attack-surface lab

A single Host-routed FastAPI app standing in for ~20 AI-native and
conventional services (MCP servers, a vector store, a model registry, a
notebook server, plus a handful of conventional contrast cases), built to
prove kiyooo's AI-asset detection against something closer to a real
environment than a unit-test fixture. Same rule as `labs/acmecorp/`:
everything here is decoy-grade, never exploit-grade — no code path here
executes an attacker's input, only serves realistic-looking static
responses.

**Honesty note, read this first:** every service's response shape was
verified directly against kiyooo's real fingerprint catalog
(`kiyooo/detect/fingerprints/ai.yaml`) and category `detect:` predicates
(`org-context.example/categories/05-ai-assets/*.yaml`) — each endpoint was
requested in-process (`starlette.testclient.TestClient`) and its response
checked against the exact regex/header pattern kiyooo's pipeline matches
on, not just eyeballed for plausibility. What has **not** been run: the
full `docker compose up` -> `kiyooo scan` -> `kiyooo triage` chain against
the live containers, because this environment has no running Docker
daemon. **Rehearse that full chain once yourself before relying on this**
— same caveat `labs/acmecorp/README.md` gives, for the same reason.

## Setup (once)

```bash
# Point every lab hostname at localhost. KIYOO_LAB_DOMAIN defaults to
# kiyoo-ai.lab specifically so this never collides with a real domain.
for name in mcp-docs mcp-ops mcp-legacy llm chat vectors qdrant mlflow \
            notebook models ai-portal internal-tools staging admin portal \
            sso api git files shop legacy db kiyoo-ai; do
  echo "127.0.0.1 ${name}.kiyoo-ai.lab" | sudo tee -a /etc/hosts
done
for i in $(seq -w 1 10); do
  echo "127.0.0.1 n0${i}.kiyoo-ai.lab" | sudo tee -a /etc/hosts
done
```

## Run

```bash
docker compose -f labs/kiyoo-ai/docker-compose.yml up -d --wait
```

Every hostname above is served on `http://<name>.kiyoo-ai.lab:8000/`
(one shared port — Starlette's `Host()` routing dispatches by the `Host`
header, not the port, so this works on any port you map). The MySQL
handshake decoy is the one exception: real TCP on `db.kiyoo-ai.lab:3307`
(3306 is acmecorp's own MySQL decoy — kept distinct so `kiyoo-labs` can
run both labs together with no port collision).

```bash
curl http://mcp-docs.kiyoo-ai.lab:8000/
curl -X POST http://mcp-ops.kiyoo-ai.lab:8000/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Point `kiyooo scan -d kiyoo-ai.lab` (or `kiyoo-cli`, see `../../kiyooo/cli_quick.py`)
at these hostnames the same way you'd point it at any target, once they're
in your `scope.yaml`.

## Reset

```bash
docker compose -f labs/kiyoo-ai/docker-compose.yml down -v
```

## The drift scenario

```bash
./scenarios/dev-exposes-prod.sh   # internal-tools.kiyoo-ai.lab: 403 -> dangerous MCP catalog, live
./scenarios/undo.sh               # reset before the next run-through
```

## What's here

| Path | What |
|---|---|
| `app/` | The FastAPI app — one module per decoy service under `app/services/` |
| `docker-compose.yml`, `Dockerfile`, `requirements.txt` | Standalone; does not import the `kiyooo` package, so it can deploy to a public VPS on its own |
| `expected.yaml` | Hand-verified expected-findings matrix — reference data, not wired to a CLI command (see the note at the top of that file for why) |
| `PLANTED_SECRETS.md` | Inventory of every fake credential/artifact this lab serves, and proof each is fake |
| `scenarios/` | The drift demo scripts |

## Deploying this publicly

A public deployment needs more than what's implemented here: account
isolation, egress-deny, rate limits, a `security.txt`, and a disclosure
notice are all real requirements before pointing real DNS at this.
Nothing in this lab currently implements them; they belong at the
infrastructure layer (reverse proxy / cloud config), not in this app.
