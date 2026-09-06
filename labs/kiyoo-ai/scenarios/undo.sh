#!/usr/bin/env bash
# Resets the drift scenario — run this before the next demo run-through.
set -euo pipefail

COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml"

echo "==> disabling internal-tools.kiyoo-ai.lab (back to 403, allowlist restored)"
docker compose -f "$COMPOSE_FILE" exec -T app rm -f /tmp/kiyoo-ai-drift-enabled
echo "==> done"
