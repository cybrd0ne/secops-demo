# Risk Register — secops-demo

Written before any code. Every control in this repository answers a row here, and
every pull request cites the risk IDs it closes. This is the reference register for
Module 4A: a small self-hosted log-enrichment and detection stack, driven by AI
configuration, governed through CI/CD, and enriched with live threat intelligence.

Three registers are in scope. Operational risk is risk the AI agent introduces in the
engineering workflow. Internal risk is risk in the security function this project
serves. External risk is risk from the live threat landscape.

Score likelihood and impact 1 to 5 (see Scales). Inherent score is likelihood times
impact. Residual score is scored again after the control. A row marked Implemented or
Verified must point to something a reviewer can open in the clone.

## Register

| ID | Register | Asset | Threat / technique | ATT&CK | L | I | Inherent | Control | RL | RI | Residual | Evidence | Status |
|----|----------|-------|--------------------|--------|---|---|----------|---------|----|----|----------|----------|--------|
| R-01 | Operational | main branch | AI agent commits code bypassing review | — | 4 | 4 | 16 (High) | Ruleset: PR required, status checks required, no direct push; evidence-based governance workflow on Free | 1 | 4 | 4 (Low) | `docs/ruleset-main.json`; `.github/workflows/governance.yml`; `.pre-commit-config.yaml` | Verified |
| R-02 | Operational | Repository secrets | Agent or student commits a plaintext API key or password | T1552.001 | 4 | 5 | 20 (High) | pre-commit gitleaks hook plus SOPS/age for all secrets; only ciphertext committed | 2 | 3 | 6 (Low) | `.pre-commit-config.yaml`; `.sops.yaml`; `secrets/opensearch.enc.yaml` | Verified |
| R-03 | Internal | Logstash enrichment pipeline | Malformed log input breaks normalisation, detections go blind | — | 3 | 4 | 12 (Medium) | pytest suite with positive and negative samples, run in CI on every pull request | 1 | 4 | 4 (Low) | `tests/test_sigma_dns_txt.py`; `tests/samples/`; `.github/workflows/ci.yml` | Verified |
| R-04 | External | Host telemetry | Traffic from known-malicious IPs goes unflagged | T1071 | 4 | 4 | 16 (High) | MISP feed to translate filter, telemetry tagged `threat.indicator.matched` and risk-scored | 2 | 3 | 6 (Low) | `scripts/misp_pull.py`; `pipelines/suricata.conf`; `docs/evidence/` | Verified |
| R-05 | External | Public-facing nginx front door | Exposed service version indexed by Shodan | T1595.002 | 3 | 3 | 9 (Medium) | Weekly Shodan query on own IP, alert on a new open port or banner | 1 | 3 | 3 (Low) | `scripts/exposure_check.py`; `monitoring/alerts.yml` | Implemented |

## How each control lands in the repository

**R-01** is closed by the ruleset exported to `docs/ruleset-main.json` and, on a GitHub
Free account, by the governance workflow that fails whenever a commit reaches `main`
without a merged pull request. The `no-commit-to-branch` pre-commit hook stops the
mistake locally before it ever reaches the remote.

**R-02** is closed twice. gitleaks runs in pre-commit and refuses a commit that carries
a key. Real secrets never sit in the tree as plaintext: `.sops.yaml` binds the
`secrets/` path to an age recipient, and `secrets/opensearch.enc.yaml` holds ciphertext
only. The age private key stays on the machine and never enters the repository.

**R-03** is closed by treating detection content as code. Every rule ships a positive
and a negative sample, and `tests/test_sigma_dns_txt.py` asserts the rule matches one
and not the other. The test runs in `ci.yml`, so a change that breaks normalisation
fails the pull request.

**R-04** is closed by pulling indicators from MISP into `enrich/ioc_ip.yml` and reading
them in the Logstash `translate` filter. A log line whose destination matches a known-bad
indicator is tagged `threat.indicator.matched` and given a risk score. The clean line is
untouched. That difference is the evidence that enrichment changes an outcome.

**R-05** is closed by querying Shodan for the stack's own public IP and alerting when a
new port or banner appears. `scripts/exposure_check.py` produces the daily diff and the
Alertmanager rule in `monitoring/alerts.yml` carries the alert.

## Scales

| Score | Likelihood | Impact |
|-------|-----------|--------|
| 1 | Rare: no realistic path with current controls | Negligible: no effect on C, I or A |
| 2 | Unlikely: needs unusual conditions or insider error | Minor: contained, fixed in hours, no data exposure |
| 3 | Possible: plausible within the project lifetime | Moderate: one component degraded, limited exposure |
| 4 | Likely: expected without the control | Major: detections blind or secrets exposed |
| 5 | Almost certain: already observed or trivially triggered | Severe: full compromise of the project or its credentials |

Score bands on likelihood times impact: 1–7 Low, 8–14 Medium, 15–25 High.

## Status values

Open, Implemented (control exists), Verified (evidence reviewed), Accepted (risk left
as is, with the reason in the Control column).
