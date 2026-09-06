.PHONY: dev test migrate lint fmt down lab-up lab-reset lab-demo lab-down \
	lab-ai-up lab-ai-reset lab-ai-down

dev:
	docker compose up -d
	@echo "waiting for postgres..."
	@until docker compose exec -T postgres pg_isready -U kiyooo >/dev/null 2>&1; do sleep 1; done
	uv run alembic upgrade head

migrate:
	uv run alembic upgrade head

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run mypy kiyooo

fmt:
	uv run ruff format .
	uv run ruff check --fix .

down:
	docker compose down

# The acmecorp demo lab. Requires kiyooo's own
# `make dev` stack (Postgres/Redis/MinIO) already running, plus
# org_context_path pointed at org-context.example (the default). See
# labs/acmecorp/README.md before your first run.
lab-up:
	uv run --with cryptography python labs/acmecorp/seed/gen_expired_cert.py labs/acmecorp/certs
	docker compose -f labs/acmecorp/docker-compose.yml up -d --wait
	uv run python labs/acmecorp/seed/gen_junk_findings.py > labs/acmecorp/seed/junk-findings.csv
	uv run kiyooo ingest run --file labs/acmecorp/seed/junk-findings.csv --format csv \
		--csv-asset-col Host --csv-issue-type-col Type --csv-asset-type tcp_service
	@echo ""
	@echo "acmecorp lab is up. Seeds: mysql:3306, staging:8081, ollama:11434,"
	@echo "minio:9500 (bucket seeded async, check 'docker compose -f"
	@echo "labs/acmecorp/docker-compose.yml logs minio-seed'), leaky-secret:8082,"
	@echo "expired-cert:8443 (40 vhosts), sso-admin:8083, + 200 imported findings."
	@echo "Run: uv run kiyooo scan --seeds labs/acmecorp/seeds.txt --profile standard"

# Full teardown + reseed — under 60 seconds once images are already
# pulled (first run pulls images and won't be as fast).
lab-reset: lab-down lab-up

# Refuses to start if the configured LLM providers would need egress —
# the whole pitch is that this runs with wifi off. Point both bulk and
# escalation at a local Ollama before a real conference floor demo.
lab-demo:
	@if [ "$${KIYOOO_LLM_PROVIDER:-ollama}" != "ollama" ]; then \
		echo "KIYOOO_LLM_PROVIDER=$${KIYOOO_LLM_PROVIDER} needs egress — set it to ollama for an air-gapped demo." >&2; \
		exit 1; \
	fi
	@if [ "$${KIYOOO_ESCALATION_PROVIDER:-ollama}" != "ollama" ]; then \
		echo "KIYOOO_ESCALATION_PROVIDER=$${KIYOOO_ESCALATION_PROVIDER} needs egress — set it to ollama, or expect escalation passes to fail closed, for an air-gapped demo." >&2; \
		exit 1; \
	fi
	$(MAKE) lab-up
	@echo "air-gap check passed — both LLM passes are local-only. Ready for labs/scenarios/dev-exposes-prod.sh."

lab-down:
	docker compose -f labs/acmecorp/docker-compose.yml down -v

# The AI attack-surface lab (labs/kiyoo-ai/) — standalone, does not import
# the kiyooo package. See labs/kiyoo-ai/README.md for the /etc/hosts
# entries it needs before this is reachable by name.
lab-ai-up:
	docker compose -f labs/kiyoo-ai/docker-compose.yml up -d --wait
	@echo ""
	@echo "kiyoo-ai lab is up on port $${KIYOO_AI_PORT:-8000} (Host-routed —"
	@echo "same port for every *.kiyoo-ai.lab hostname) and db:3307."
	@echo "See labs/kiyoo-ai/README.md for the /etc/hosts entries."

lab-ai-reset: lab-ai-down lab-ai-up

lab-ai-down:
	docker compose -f labs/kiyoo-ai/docker-compose.yml down -v
