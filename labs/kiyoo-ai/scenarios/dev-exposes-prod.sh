#!/usr/bin/env bash
# The drift scenario — the live moment in the demo.
#
# Before: internal-tools.kiyoo-ai.lab -> 403, no MCP advertised.
# After:  the same catalog as mcp-ops (query_customer_db, send_email,
#         run_shell, read_file) appears live, no restart.
#
# Then:  kiyooo scan --incremental against this lab should produce an
# ASSET_NEW + AUTH_REMOVED change event, straight into critical triage.
# Run scenarios/undo.sh to reset before the next run-through.
set -euo pipefail

COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml"

echo "==> enabling internal-tools.kiyoo-ai.lab (dev config leaking to what looks like prod)"
docker compose -f "$COMPOSE_FILE" exec -T app touch /tmp/kiyoo-ai-drift-enabled
echo "==> done — internal-tools.kiyoo-ai.lab now advertises the dangerous tool catalog"
echo "    re-scan this lab now to see the change event."
