#!/usr/bin/env bash
# Stage 12's "money shot" — live, on screen: a dev removes the
# auth gateway in front of the admin panel, and kiyooo goes change event
# -> triage -> owner attribution -> drafted ticket without anyone typing
# more than this one command. Run `make lab-up` first.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../acmecorp"

echo "== before: admin.acmecorp.lab/admin redirects to SSO =="
curl -sS -o /dev/null -w 'HTTP %{http_code} -> %{redirect_url}\n' http://localhost:8083/admin || true

echo
echo ">> a developer just removed the SSO gateway in front of the admin panel <<"
cp nginx-conf/sso-admin-panel-no-auth.conf /tmp/acmecorp-drift.conf
docker compose cp /tmp/acmecorp-drift.conf sso-admin-panel:/etc/nginx/conf.d/default.conf
docker compose exec sso-admin-panel nginx -s reload
rm -f /tmp/acmecorp-drift.conf

echo
echo "== after: admin.acmecorp.lab/admin now serves the panel directly =="
curl -sS http://localhost:8083/admin
echo

start=$(date +%s)
echo
echo "== kiyooo events handle: scan -> detect -> triage -> route, one command =="
# Bare hostname, not host:port — kiyooo's recon adapters discover the port
# themselves. Port 8083 is non-standard; confirm during rehearsal that
# your naabu port range covers it (see labs/acmecorp/README.md), or this
# step won't find anything to re-triage.
uv run kiyooo events handle "admin.acmecorp.lab" --kind deploy
elapsed=$(( $(date +%s) - start ))
echo
echo "done in ${elapsed}s — check the approval queue / ticket sink for the drafted ticket."
echo "revert with: docker compose cp nginx-conf/sso-admin-panel.conf sso-admin-panel:/etc/nginx/conf.d/default.conf && docker compose exec sso-admin-panel nginx -s reload"
