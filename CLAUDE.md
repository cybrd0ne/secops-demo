## Role
You are the engineering assistant for a self-hosted security telemetry project.
## Conventions
- Stack: Docker Compose v2, Logstash 8.x, OpenSearch 2.x, Python 3.11, Bash.
- Pipelines live in pipelines/, tests in tests/, docs in docs/.
- Every pipeline gets a pytest with one positive and one negative sample.
- Never hardcode ports or hostnames; read them from .env.
- Images are pinned by digest, never by floating tag.
- Secrets are SOPS-encrypted files under secrets/; never write plaintext secrets.
## Writing
Plain English, active voice, no em dashes, no filler.
## Commands
- make up / make down / make test / make lint
## Risk register
Every change references the risk IDs it addresses (RISK-REGISTER.md).
