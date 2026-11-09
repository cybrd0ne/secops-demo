# Lab 5: Detection as Code

You will write a Sigma rule for DNS tunnelling (MITRE ATT&CK T1071.004), teach the
Logstash pipeline to read DNS answers in the Elastic Common Schema (ECS), convert the
rule to an OpenSearch query and prove it with tests that run in the Lab 4 pipeline. By
the end, a rule that stops matching its sample fails your pull request before anyone
merges it.

This lab closes risk **R-03** (normalisation breaks and detections go blind) for
detection content. Reference it in your commits and in your pull request.

## What you need

- Lab 3 stack running (`make up` reaches green) and the Lab 4 CI workflow merged on `main`
- Python 3.10 or newer (CI uses 3.11)
- Docker, for the Logstash image the pipeline tests run in
- About 15 minutes of quiet for the tuning step in Part D. It is the part that matters.

Work on a branch. `main` only accepts pull requests (R-01).

```bash
git switch main && git pull --ff-only
git switch -c lab5/detection
```

## Part A: Prepare your machine

### 1. Add the detection tools to the test dependencies

CI installs `requirements-dev.txt`, so whatever your tests need goes there, pinned.
Replace the file with:

```
# Test dependencies for the CI "test" job and `make test`.
# Pinned exactly so every run installs the same version.
pytest==9.2.0
PyYAML==6.0.3
sigma-cli==3.1.0
pySigma-backend-opensearch==2.0.3
```

Install them in a local virtual environment (`.venv/` is already git-ignored):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
sigma list targets | grep opensearch
```

You should see `opensearch_lucene`. That is the backend name you convert to, not
`opensearch`.

### 2. Pin the Logstash image

The pipeline tests and the stack both run Logstash from `LOGSTASH_IMAGE` in `.env`. Use
the OpenSearch build of Logstash, because the stock image has no OpenSearch output.
Check Docker Hub for the newest 8.x tag first; 8.9.0 is the known-good fallback.

```bash
docker pull opensearchproject/logstash-oss-with-opensearch-output-plugin:8.9.0
docker inspect --format '{{index .RepoDigests 0}}' \
  opensearchproject/logstash-oss-with-opensearch-output-plugin:8.9.0
```

Add the digest form to `.env`, never the tag:

```
LOGSTASH_IMAGE=opensearchproject/logstash-oss-with-opensearch-output-plugin@sha256:<digest>
```

Run `make test`. The two existing pipeline tests should now run instead of skipping.

## Part B: Teach the pipeline to read DNS answers

A rule can only match fields that exist. Suricata writes DNS answers in its own
format, so normalisation comes first. This is the main lesson of the session: the rule
you write in Part C works only because of the mapping you write here.

### 1. Map DNS answers to ECS

Open `pipelines/suricata.conf` and replace the `dns` branch with:

```
    } else if [suricata][eve][event_type] == "dns" {
      mutate {
        rename => {
          "[suricata][eve][dns][rrname]" => "[dns][question][name]"
          "[suricata][eve][dns][rrtype]" => "[dns][question][type]"
          "[suricata][eve][dns][type]"   => "[dns][type]"
        }
      }
      ruby {
        code => '
          answers = event.get("[suricata][eve][dns][answers]")
          if answers.is_a?(Array)
            event.set("[dns][answers]", answers.map { |a|
              { "name" => a["rrname"], "type" => a["rrtype"], "ttl" => a["ttl"], "data" => a["rdata"] }
            })
            event.remove("[suricata][eve][dns][answers]")
          end
        '
      }
```

`mutate` cannot rename keys inside a list, so the `ruby` block rewrites each answer to
the ECS names `dns.answers.name`, `type`, `ttl` and `data`.

### 2. Fix the field types in OpenSearch

Without a template, OpenSearch maps every string as analysed text with a keyword copy
that drops values longer than 256 characters. A long TXT answer, the very thing you want
to catch, would never be searchable as a whole value. Create
`config/opensearch/suricata-template.json`:

```json
{
  "index_patterns": ["suricata-*"],
  "template": {
    "mappings": {
      "properties": {
        "source": {"properties": {"ip": {"type": "ip"}}},
        "destination": {"properties": {"ip": {"type": "ip"}}},
        "dns": {
          "properties": {
            "type": {"type": "keyword"},
            "question": {"properties": {
              "name": {"type": "keyword"},
              "type": {"type": "keyword"}
            }},
            "answers": {"properties": {
              "name": {"type": "keyword"},
              "type": {"type": "keyword"},
              "data": {"type": "keyword", "ignore_above": 8191}
            }}
          }
        }
      }
    }
  }
}
```

You apply it in Part E, before the first `suricata-*` index exists.

## Part C: Write and convert the rule

### 1. Write the rule

Generate your own rule ID with `python3 -c "import uuid; print(uuid.uuid4())"`, then
create `detections/sigma/dns_long_txt.yml`:

```yaml
title: Long DNS TXT answer
id: <your uuid>
status: experimental
description: A DNS TXT answer of 200 characters or more, a common carrier for C2 commands or exfiltrated data.
references:
  - https://attack.mitre.org/techniques/T1071/004/
author: <your name>
date: 2026-11-09
tags:
  - attack.command-and-control
  - attack.t1071.004
logsource:
  product: suricata
  service: dns
detection:
  answer:
    dns.type: answer
    dns.answers.type: TXT
  long_data:
    dns.answers.data|re: '.{200,}'
  condition: answer and long_data
falsepositives:
  - Domain-verification and long SPF TXT records on mail and SaaS domains
level: medium
```

The field names are already ECS, the names your pipeline writes. Leave the regex
unanchored: OpenSearch regular expressions always match the whole value.

### 2. Convert it

```bash
mkdir -p detections/opensearch
sigma convert -t opensearch_lucene --without-pipeline \
  detections/sigma/dns_long_txt.yml
sigma convert -t opensearch_lucene --without-pipeline -f dsl_lucene \
  detections/sigma/dns_long_txt.yml > detections/opensearch/dns_long_txt.json
```

The first command prints the Lucene query you will paste into Discover. The second saves
the query DSL that you commit. `--without-pipeline` tells sigma-cli not to rename fields.
That is correct here only because Part B already did the normalisation in Logstash.

## Part D: Samples and tests

Every rule ships a positive sample, a negative sample with at least one near miss, and a
test. You test at two layers. The rule layer runs everywhere, CI included. The pipeline
layer runs the real Logstash and needs `LOGSTASH_IMAGE`.

### 1. Generate the samples

Create `tests/samples/make_dns_samples.py`:

```python
"""Write the DNS TXT samples for Lab 5: raw Suricata EVE and the ECS it becomes."""
import base64
import json
from pathlib import Path

samples = Path("tests/samples")
blob = base64.b64encode(bytes(range(180))).decode()  # 240 characters, looks like encoded data
dkim = "v=DKIM1; k=rsa; p=" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" * 5  # long but benign


def eve(name, rtype, data=None, kind="answer"):
    dns = {"version": 2, "type": kind, "id": 4242, "rrname": name, "rrtype": rtype, "rcode": "NOERROR"}
    if kind == "answer":
        dns["answers"] = [{"rrname": name, "rrtype": rtype, "ttl": 60, "rdata": data}]
    return {"timestamp": "2026-11-09T10:00:00.000000+0000", "flow_id": 1, "in_iface": "eth0",
            "event_type": "dns", "src_ip": "10.0.0.53", "src_port": 53, "dest_ip": "10.0.0.5",
            "dest_port": 40000, "proto": "UDP", "dns": dns}


def ecs(rec):
    """The fields the rule reads, as pipelines/suricata.conf writes them."""
    d = rec["dns"]
    out = {"type": d["type"], "question": {"name": d["rrname"], "type": d["rrtype"]}}
    if "answers" in d:
        out["answers"] = [{"name": a["rrname"], "type": a["rrtype"], "ttl": a["ttl"],
                           "data": a["rdata"]} for a in d["answers"]]
    return {"event": {"module": "suricata", "dataset": "suricata.eve"}, "dns": out}


positive = [eve("a1b2c3.updates.example.net", "TXT", blob)]
negative = [
    eve("example.com", "TXT", "v=spf1 include:_spf.example.com ~all"),  # short TXT
    eve("a1b2c3.updates.example.net", "TXT", kind="query"),             # query, no answer
    eve("selector1._domainkey.example.com", "TXT", dkim),                # long but benign
]
for name, records in [("positive", positive), ("negative", negative)]:
    lines = lambda f: "".join(json.dumps(f(r)) + "\n" for r in records)
    (samples / f"eve_dns_txt_{name}.json").write_text(lines(lambda r: r))
    (samples / f"ecs_dns_txt_{name}.json").write_text(lines(ecs))
print("4 sample files written to", samples)
```

Run it from the repo root with `python3 tests/samples/make_dns_samples.py`. The `eve_*`
files are what Suricata writes. The `ecs_*` files are what your pipeline should turn them
into, and the pipeline test below checks that claim against real Logstash.

### 2. Add a Sigma matcher for tests

CI has no OpenSearch, so a small helper evaluates the rule file itself in Python. The
test reads the same YAML you convert, so the rule cannot drift away from its test.
Create `tests/sigma_match.py`:

```python
"""Evaluate a Sigma rule against ECS events in Python, so CI can test rule logic.

Supports what this course uses: field lists (OR), the modifiers contains,
startswith, endswith and re, and conditions built from selection names with
and, or, not and parentheses. Matching follows the OpenSearch query the rule
converts to: plain values ignore case, re must match the whole value.
"""
import re
from pathlib import Path

import yaml


def _values(event, dotted):
    """Every value at a dotted ECS path, walking into lists."""
    found = [event]
    for key in dotted.split("."):
        nxt = []
        for node in found:
            items = node if isinstance(node, list) else [node]
            nxt += [i[key] for i in items if isinstance(i, dict) and key in i]
        found = nxt
    flat = []
    for v in found:
        flat += v if isinstance(v, list) else [v]
    return [str(v) for v in flat]


def _field_ok(event, spec, wanted):
    field, *mods = spec.split("|")
    wanted = wanted if isinstance(wanted, list) else [wanted]
    for have in _values(event, field):
        for w in map(str, wanted):
            if "re" in mods and re.fullmatch(w, have, re.DOTALL):
                return True
            h, w2 = have.lower(), w.lower()
            if "contains" in mods and w2 in h:
                return True
            if "startswith" in mods and h.startswith(w2):
                return True
            if "endswith" in mods and h.endswith(w2):
                return True
            if not mods and h == w2:
                return True
    return False


def _selection_ok(event, selection):
    return all(_field_ok(event, k, v) for k, v in selection.items())


def rule_matches(rule_path, event):
    det = yaml.safe_load(Path(rule_path).read_text())["detection"]
    tokens = re.findall(r"\(|\)|[\w.]+", det["condition"])
    pos = 0

    def expr():
        nonlocal pos
        val = term()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            val = term() or val
        return val

    def term():
        nonlocal pos
        val = factor()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            val = factor() and val
        return val

    def factor():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        if tok == "not":
            return not factor()
        if tok == "(":
            val = expr()
            pos += 1
            return val
        return _selection_ok(event, det[tok])

    return expr()
```

### 3. Write the rule tests

Create `tests/test_sigma_dns_txt.py`:

```python
"""Detection as code for the long DNS TXT rule (RISK-REGISTER R-03)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sigma_match import rule_matches

ROOT = Path(__file__).resolve().parent.parent
RULE = ROOT / "detections/sigma/dns_long_txt.yml"
QUERY = ROOT / "detections/opensearch/dns_long_txt.json"
SAMPLES = ROOT / "tests/samples"


def load(name):
    lines = (SAMPLES / name).read_text().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def test_rule_fires_on_positive_sample():
    assert all(rule_matches(RULE, ev) for ev in load("ecs_dns_txt_positive.json"))


def test_rule_stays_quiet_on_negative_sample():
    assert not any(rule_matches(RULE, ev) for ev in load("ecs_dns_txt_negative.json"))


@pytest.mark.skipif(not shutil.which("sigma"), reason="sigma-cli not installed")
def test_committed_query_matches_the_rule():
    out = subprocess.run(
        ["sigma", "convert", "-t", "opensearch_lucene", "--without-pipeline",
         "-f", "dsl_lucene", str(RULE)],
        capture_output=True, text=True, check=True,
    ).stdout
    assert json.loads(out) == json.loads(QUERY.read_text())
```

The last test catches a rule edited without reconverting the committed query.

### 4. Chain the rule to the real pipeline

Add to `tests/test_suricata_ecs.py`, below the existing tests:

```python
from sigma_match import rule_matches

RULE = ROOT / "detections/sigma/dns_long_txt.yml"


def test_dns_answer_maps_to_ecs_and_fires_the_rule():
    events = run_pipeline(ROOT / "tests/samples/eve_dns_txt_positive.json")
    assert events and all(rule_matches(RULE, ev) for ev in events)


def test_negative_dns_samples_stay_quiet_after_the_pipeline():
    events = run_pipeline(ROOT / "tests/samples/eve_dns_txt_negative.json")
    assert len(events) == 3 and not any(rule_matches(RULE, ev) for ev in events)
```

These run raw Suricata output through your Logstash pipeline and apply the rule to what
comes out. If Part B is wrong, they fail even when the rule tests pass.

### 5. Run the tests and tune the rule

```bash
make test
```

`test_rule_stays_quiet_on_negative_sample` fails. The DKIM key in the third negative
record is a long TXT answer too, and DKIM records exist on almost every mail domain. In
production this rule would page someone every few minutes. This failure is the point of
the exercise: the negative sample found a false positive before an analyst did.

Tune the rule. Add a selection under `detection:` and extend the condition:

```yaml
  dkim:
    dns.question.name|contains: '._domainkey.'
  condition: answer and long_data and not dkim
```

Reconvert (repeat both commands from Part C step 2) and run `make test` again. Every
test passes. Commit the rule, the query, the samples, the generator and the tests
together, for example `feat(detect): long DNS TXT rule with DKIM tuning (R-03)`.

## Part E: See it fire in OpenSearch

### 1. Add an input and an output

`pipelines/suricata.conf` only holds filters, so the test harness can feed it. The stack
needs its own input and output files. Create `pipelines/00-input-file.conf`:

```
input {
  file {
    path => "/data/*.json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => plain
  }
}
```

and `pipelines/99-output-opensearch.conf`:

```
output {
  opensearch {
    hosts => ["https://opensearch:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
    user => "admin"
    password => "${OPENSEARCH_INITIAL_ADMIN_PASSWORD}"
    ssl => true
    ssl_certificate_verification => false
  }
}
```

Match the host to your OpenSearch service name in `compose.yaml`. Certificate checks are
off because OpenSearch uses its self-signed demo certificate. That is acceptable in this
lab and nowhere else.

### 2. Add Logstash to the stack

Add the service to `compose.yaml`:

```yaml
  logstash:
    image: ${LOGSTASH_IMAGE}
    environment:
      OPENSEARCH_INITIAL_ADMIN_PASSWORD: ${OPENSEARCH_INITIAL_ADMIN_PASSWORD}
    volumes:
      - ./pipelines:/usr/share/logstash/pipeline:ro
      - ./data:/data:ro
    depends_on:
      - opensearch
```

Replay files land in `data/`, which never belongs in git:

```bash
mkdir -p data
echo "data/" >> .gitignore
make up
```

### 3. Apply the template, then replay

Apply the template while `data/` is still empty, so no `suricata-*` index exists yet. The
password goes to curl on stdin, not on the command line where `ps` would show it.

```bash
set -a; . ./.env; . ./.env.secrets; set +a
curl -sk -K- -X PUT "https://localhost:${OPENSEARCH_PORT}/_index_template/suricata" \
  -H 'Content-Type: application/json' \
  --data @config/opensearch/suricata-template.json \
  <<< "user = \"admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}\""
```

Expect `{"acknowledged":true}`. Now feed Logstash the samples:

```bash
cp tests/samples/eve_dns_txt_positive.json tests/samples/eve_dns_txt_negative.json data/
docker compose logs -f logstash
```

Logstash picks up new files within about 15 seconds. Stop following the logs with Ctrl+C
once it settles.

### 4. Find the hit in Dashboards

1. Open Dashboards, go to Dashboards Management, Index patterns, and create `suricata-*`
   with `@timestamp` as the time field.
2. In Discover, choose the `suricata-*` pattern and set the time range to include
   9 November 2026, the timestamp in the samples.
3. Switch the query language from DQL to Lucene. DQL has no regular expressions, and the
   query looks broken until you switch.
4. Paste the Lucene query printed by `sigma convert`.

You get exactly one hit: the `a1b2c3.updates.example.net` answer. Search for
`dns.question.type:TXT` to see all four records, so you can show that the other three
were indexed and correctly ignored. Take a screenshot of the single hit for
`docs/evidence/`.

## Part F: Your own rule (graded)

Write a second rule on your own. It must describe a technique you can show in your own
Suricata or Zeek telemetry, with an ATT&CK tag. Some starting points:

- An HTTP user agent that real browsers never send (T1071.001)
- DNS queries with unusually long subdomain labels (T1048.003)
- A Suricata alert from a specific ruleset category, raised above its default severity
- TLS to a destination port that is not 443 for a protocol that expects it

Hold it to the same standard as the DNS rule: ECS field names, a converted query
committed under `detections/opensearch/`, positive and negative samples with at least
one realistic near miss, a rule test and a pipeline test. If your rule needs fields the
pipeline does not map yet, map them first. If you use Zeek logs, you need a Zeek
normalisation pipeline with its own tests before the rule can work.

## Check your work

Before you open the pull request, every line here must hold:

- [ ] `make test` passes with `LOGSTASH_IMAGE` set and nothing skipped.
- [ ] Each rule has an ATT&CK tag, a `falsepositives` entry and its own UUID.
- [ ] Each negative sample contains at least one near miss, not just unrelated noise.
- [ ] `detections/opensearch/` matches a fresh `sigma convert` of every rule.
- [ ] Discover shows exactly one hit for the DNS rule, and the screenshot is in `docs/evidence/`.
- [ ] `git status` lists nothing under `data/`.
- [ ] Your commits and the pull request description mention R-03.

Push the branch, open the pull request and watch the `test` job in CI. It must go green
before you ask for review.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `'opensearch' is not one of 'lucene', ..., 'opensearch_lucene'` | The plugin is called `opensearch`, but the target is `opensearch_lucene`. |
| `sigma convert` stops and talks about processing pipelines | Add `--without-pipeline`. Your rule already uses ECS names. |
| Discover reports a syntax error, or the regex query finds nothing | The query language is still DQL. Switch to Lucene, and check the time range covers 9 November 2026. |
| The query finds nothing although the record is in Discover | The index was created before the template. Delete the `suricata-*` index, empty `data/`, run `docker compose rm -sf logstash && make up`, apply the template and replay. |
| `GET suricata-*/_mapping/field/dns.answers.data` shows `text` | Same cause as above: the template did not apply before indexing. |
| Logstash does not re-read the samples after a restart | Remove the container, do not just restart it: `docker compose rm -sf logstash && make up`. |
| Logstash says it cannot find an output plugin named `opensearch` | `LOGSTASH_IMAGE` points at the stock Logstash image. Use `logstash-oss-with-opensearch-output-plugin`. |
| The pipeline tests are skipped | `LOGSTASH_IMAGE` is missing from `.env`, or `make test` was run outside the repo root. |
| `test_committed_query_matches_the_rule` fails | You changed the rule and did not reconvert. Rerun both commands from Part C step 2. |
| Your own Suricata output has no `answers` list | Suricata 8 writes EVE DNS version 3, with a different layout. Check `"version"` inside `dns`, then adapt the `ruby` block and regenerate the samples to match. |
