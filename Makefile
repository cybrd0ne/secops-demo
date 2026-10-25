# Ports, hostnames and image digests come from .env (see CLAUDE.md).
.PHONY: up down test lint secrets

# Decrypt the SOPS secret for compose; owner-only, deleted by make down (R-02).
secrets:
	umask 077 && sops -d secrets/opensearch.enc.yaml | sed 's/: /=/' > .env.secrets

up: secrets
	docker compose --env-file .env --env-file .env.secrets up -d

down:
	docker compose down -v && rm -f .env.secrets

# Pipeline tests read LOGSTASH_IMAGE from .env and skip without it (R-03).
test:
	set -a; [ ! -f .env ] || . ./.env; set +a; python3 -m pytest tests/

lint:
	pre-commit run --all-files
