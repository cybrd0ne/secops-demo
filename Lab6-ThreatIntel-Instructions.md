# Lab 6: Threat Intelligence Enrichment

You will run MISP, pull its indicators into a lookup file, and have Logstash tag any
telemetry that talks to a known-bad address and raise its risk score. Then you will ask
Shodan what the internet already sees on your own public IP. Enrichment counts only when
it changes an outcome, so the evidence for this lab is a before and after: the same
pipeline, two records, and only the bad one flagged.

This lab closes risk **R-04** (traffic from known-malicious IPs goes unflagged) and
builds the data half of **R-05** (exposed service indexed by Shodan). Lab 7 adds the
alert for R-05. Reference both IDs in your commits and in your pull request.

## Rules of engagement

Read these before you run anything. They are graded.

- Query Shodan only for an IP you own or are authorised to assess, such as your home
  router's WAN address with the account holder's permission. Never a classmate's, the
  university's or a third party's address.
- Indicators from MISP are live intelligence. Never commit `enrich/ioc_ip.yml`, and
  respect the TLP tag on each event: TLP:AMBER and above stay off screenshots you share.
- API keys go through SOPS, exactly like the OpenSearch password in Lab 3 (R-02).
- `secops-demo` is a public repository and your public IP is personal data. Keep it out
  of commits and redact it in every screenshot.

## What you need

- Lab 5 merged, and the stack running with Logstash
- Enough Docker memory for MISP's extra containers on top of the stack. If OpenSearch
  starts failing once MISP is up, raise the Docker Desktop memory limit.
- A free Shodan account and its API key (account page, "API Key")
- A public IP that the rules of engagement allow you to query

Work on a branch:

```bash
git switch main && git pull --ff-only
git switch -c lab6/threat-intel
```

## Part A: Run MISP (do this the evening before)

MISP's first boot and its first feed fetch are the slowest steps in the module. Never
leave them for the lab itself.

### 1. Clone MISP next to your repository, not inside it

```bash
cd ..
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
```

### 2. Move MISP off port 443

Your Lab 3 front door already owns 443. Edit `.env` in `misp-docker` and set:

```
NGINX_HTTP_PORT=8081
NGINX_HTTPS_PORT=8444
BASE_URL=https://localhost:8444
```

`BASE_URL` must include the port, or MISP builds broken links.

### 3. Start it and record what you started

```bash
docker compose pull
docker compose up -d
docker compose logs -f misp-core
```

Wait until the core container reports that MISP is ready. That takes several minutes the
first time. misp-docker runs floating `latest` images by default, which breaks the rule
you followed in Lab 3. Record what you actually pulled, so a reviewer can see the exact
versions:

```bash
docker images --digests | grep misp
```

Paste the output into `docs/misp-setup.md` in your repository, under a heading that
names the date.

### 4. Secure the admin account and create an API key

Open `https://localhost:8444` and accept the self-signed certificate. Log in as
`admin@admin.test` with password `admin` and change the password at once. Then go to
Administration, List Auth Keys, Add authentication key. Copy the key now, because MISP
shows it only once.

### 5. Enable and fetch one feed

Go to Sync Actions, Feeds. If the list is empty, load the default feed metadata. Enable
the **CIRCL OSINT Feed**, then fetch and store all feed data. Open the event list and
confirm events appear with attributes. Note the feed name and the fetch date in
`docs/misp-setup.md`.

## Part B: Keep the keys out of git

### 1. Store the secrets with SOPS

From your repository root, create a new encrypted file. `sops edit` encrypts on save,
so no plaintext copy ever touches the disk:

```bash
sops edit secrets/intel.enc.yaml
```

Enter:

```yaml
MISP_URL: https://localhost:8444
MISP_KEY: <your MISP auth key>
MISP_CA: ""
SHODAN_KEY: <your Shodan API key>
OWN_PUBLIC_IP: <your authorised public IP>
```

`MISP_CA` stays empty in this lab, which turns off certificate checks for MISP's
self-signed certificate. Point it at a CA file if you give MISP a real certificate.

### 2. Decrypt both files at deploy time

Change the `secrets` target in the `Makefile` so it decrypts both files into
`.env.secrets`:

```make
secrets:
	umask 077 && { sops -d secrets/opensearch.enc.yaml; sops -d secrets/intel.enc.yaml; } \
	  | sed 's/: /=/' > .env.secrets
```

Recipe lines start with a tab, not spaces. `make down` already deletes `.env.secrets`.

### 3. Ignore what must never be committed

```bash
printf '%s\n' 'enrich/' 'exposure/' >> .gitignore
git check-ignore -v enrich/ioc_ip.yml exposure/x.json
```

Both paths must come back as ignored.

### 4. Install the intelligence clients

They run on your machine only, so they stay out of the CI dependencies. Create
`requirements-intel.txt`:

```
pymisp==3.0.0
shodan==1.31.0
```

```bash
source .venv/bin/activate
pip install -r requirements-intel.txt
```

## Part C: Pull indicators with a feed lifecycle

A feed pulled once and never refreshed is worse than no feed. It looks like coverage and
quietly goes stale. The script below applies the whole lifecycle in one place. It keeps
only attributes flagged `to_ids`, which is MISP's trust flag for "use this in
detection". It drops anything on a MISP warninglist, such as public DNS resolvers. It
ages out attributes older than 30 days, deduplicates by IP and sorts the output so that
diffs stay small.

### 1. Write the script

Create `scripts/misp_pull.py`:

```python
"""Pull IP indicators from MISP into the Logstash lookup file (RISK-REGISTER R-04).

Feed lifecycle in one place: only attributes flagged to_ids (trust), minus
anything on a MISP warninglist (known benign), seen within MISP_MAX_AGE
(ageing out), one line per IP (deduplicated), sorted so diffs stay small.
"""
import json
import os
import sys
from pathlib import Path

OUT = Path("enrich/ioc_ip.yml")


def render(attrs):
    """Return the translate dictionary: one "ip": "misp:<event>:<category>" line per IP."""
    seen = {}
    for a in attrs:
        seen.setdefault(a.value, f"misp:{a.event_id}:{a.category}")
    return "".join(f"{json.dumps(ip)}: {json.dumps(tag)}\n" for ip, tag in sorted(seen.items()))


def main():
    import pymisp

    misp = pymisp.PyMISP(
        os.environ["MISP_URL"], os.environ["MISP_KEY"], ssl=os.environ.get("MISP_CA") or False
    )
    attrs = misp.search(
        controller="attributes",
        type_attribute=["ip-dst", "ip-src"],
        to_ids=True,
        enforce_warninglist=True,
        timestamp=os.environ.get("MISP_MAX_AGE", "30d"),
        pythonify=True,
    )
    text = render(attrs)
    if not text:
        sys.exit("MISP returned no indicators; the previous lookup file stays in place.")
    OUT.parent.mkdir(exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    tmp.write_text(text)
    tmp.replace(OUT)  # atomic, so Logstash never reads a half-written file
    print(f"{len(text.splitlines())} unique indicators written to {OUT}")


if __name__ == "__main__":
    main()
```

Two details matter. An empty result keeps the old file instead of wiping your coverage.
The write goes to a temporary file and is then renamed, so Logstash never reads half a
file.

### 2. Run it

```bash
make secrets
set -a; . ./.env.secrets; set +a
python3 scripts/misp_pull.py
head -5 enrich/ioc_ip.yml
```

Pick one IP from the file for Part E. If the script finds nothing, read the
troubleshooting table before you widen `MISP_MAX_AGE`.

### 3. Test the lifecycle without a MISP server

Create `tests/test_misp_pull.py`:

```python
"""Unit test for the MISP lookup writer (RISK-REGISTER R-04). Needs no MISP server."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("misp_pull", ROOT / "scripts/misp_pull.py")
misp_pull = importlib.util.module_from_spec(spec)
spec.loader.exec_module(misp_pull)


def attr(value, event_id, category="Network activity"):
    return SimpleNamespace(value=value, event_id=event_id, category=category)


def test_lookup_is_deduplicated_sorted_and_valid_yaml():
    text = misp_pull.render([attr("198.51.100.9", 7), attr("192.0.2.1", 3), attr("198.51.100.9", 9)])
    assert yaml.safe_load(text) == {
        "192.0.2.1": "misp:3:Network activity",
        "198.51.100.9": "misp:7:Network activity",
    }
    assert text.splitlines()[0].startswith('"192.0.2.1"')


def test_empty_feed_renders_nothing():
    assert misp_pull.render([]) == ""
```

`pymisp` is imported inside `main()`, so this test runs in CI without the MISP client
installed.

## Part D: Enrich in Logstash

### 1. Add the translate filter

In `pipelines/suricata.conf`, add this block at the end of the
`if "_jsonparsefailure" not in [tags]` block, after all the renames, so that
`destination.ip` already exists:

```
    translate {
      source => "[destination][ip]"
      target => "[threat][indicator][matched]"
      dictionary_path => "/enrich/ioc_ip.yml"
      refresh_interval => 300
    }
    if [threat][indicator][matched] {
      mutate {
        add_tag => ["threat_match"]
        add_field => { "[event][risk_score]" => "80" }
      }
      mutate { convert => { "[event][risk_score]" => "float" } }
    }
```

There is no `fallback`, so a clean record gets no `threat` field at all. That keeps it
untouched, which is exactly what you will show. Logstash rereads the dictionary every
300 seconds, so a fresh `misp_pull.py` run reaches the pipeline without a restart.

### 2. Give the pipeline tests a dictionary

Logstash refuses to start if `dictionary_path` does not exist, so every pipeline test
now needs one. Create `tests/samples/ioc_ip_test.yml` with a documentation address that
can never be a real indicator:

```yaml
"203.0.113.66": "misp:0:Network activity"
```

In `tests/test_suricata_ecs.py`, add one mount to the `docker run` command inside
`run_pipeline`, next to the other `-v` lines:

```python
        "-v", f"{ROOT / 'tests' / 'samples' / 'ioc_ip_test.yml'}:/enrich/ioc_ip.yml:ro",
```

### 3. Test the outcome, not just the mapping

Create the two samples:

```bash
printf '%s\n' '{"timestamp":"2026-11-09T11:00:00.000000+0000","flow_id":2,"event_type":"flow","src_ip":"10.0.0.5","src_port":50000,"dest_ip":"203.0.113.66","dest_port":443,"proto":"TCP"}' \
  > tests/samples/eve_flow_ioc_positive.json
printf '%s\n' '{"timestamp":"2026-11-09T11:00:01.000000+0000","flow_id":3,"event_type":"flow","src_ip":"10.0.0.5","src_port":50001,"dest_ip":"10.0.0.20","dest_port":443,"proto":"TCP"}' \
  > tests/samples/eve_flow_ioc_negative.json
```

Add to `tests/test_suricata_ecs.py`:

```python
def test_known_bad_destination_is_tagged_and_scored():
    (ev,) = run_pipeline(ROOT / "tests/samples/eve_flow_ioc_positive.json")
    assert ev["threat"]["indicator"]["matched"] == "misp:0:Network activity"
    assert "threat_match" in ev["tags"]
    assert ev["event"]["risk_score"] == 80.0


def test_clean_destination_is_untouched():
    (ev,) = run_pipeline(ROOT / "tests/samples/eve_flow_ioc_negative.json")
    assert "threat" not in ev
    assert "threat_match" not in ev.get("tags", [])
```

Run `make test`. Everything from Lab 5 must still pass alongside the new tests.

### 4. Mount the live lookup in the stack

Add one volume to the `logstash` service in `compose.yaml`:

```yaml
      - ./enrich:/enrich:ro
```

Then restart with `make down && make up`.

## Part E: Show that enrichment changed the outcome

Append one record to a known-bad IP from your lookup and one to a clean internal
address. Both use the current time, so they land in today's index:

```bash
BAD_IP=$(head -1 enrich/ioc_ip.yml | cut -d'"' -f2)
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000000+0000)
printf '%s\n' \
  "{\"timestamp\":\"$NOW\",\"event_type\":\"flow\",\"src_ip\":\"192.168.1.20\",\"dest_ip\":\"$BAD_IP\",\"proto\":\"TCP\"}" \
  "{\"timestamp\":\"$NOW\",\"event_type\":\"flow\",\"src_ip\":\"192.168.1.20\",\"dest_ip\":\"10.0.0.5\",\"proto\":\"TCP\"}" \
  > data/flows.json
```

In Discover, with the Lucene query language and a time range covering the last 15
minutes:

1. Query `tags:threat_match`. You get one record, carrying `event.risk_score` 80 and
   the MISP event ID in `threat.indicator.matched`.
2. Query `destination.ip:"10.0.0.5"`. The clean record is there, with no `threat` field
   and no tag.

Screenshot both results into `docs/evidence/`. Cover the bad IP if its MISP event is
TLP:AMBER or above.

## Part F: What Shodan already sees on your IP

Shodan scans the internet on its own schedule. Asking it about your address is passive:
you read what it has already collected and send nothing to your network. It still counts
only for addresses the rules of engagement allow.

### 1. Write the check

Create `scripts/exposure_check.py`:

```python
"""Record what Shodan already knows about your own public IP (RISK-REGISTER R-05).

Query only an address you own or are authorised to assess. One host() call per
run; the free tier rate-limits loops. Lab 7 diffs these snapshots and alerts.
"""
import json
import os
from datetime import date
from pathlib import Path


def snapshot(host):
    """Keep the fields that tell you whether your exposure changed."""
    return {
        "ip": host["ip_str"],
        "ports": sorted(host.get("ports", [])),
        "org": host.get("org"),
        "last_update": host.get("last_update"),
    }


def main():
    import shodan

    api = shodan.Shodan(os.environ["SHODAN_KEY"])
    try:
        host = api.host(os.environ["OWN_PUBLIC_IP"])
    except shodan.APIError as err:
        raise SystemExit(f"Shodan: {err}")
    snap = snapshot(host)
    out = Path("exposure") / f"{date.today()}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(snap, indent=2) + "\n")
    print(json.dumps(snap, indent=2))


if __name__ == "__main__":
    main()
```

### 2. Test it and run it once

Create `tests/test_exposure_check.py`:

```python
"""Unit test for the Shodan snapshot (RISK-REGISTER R-05). Makes no network call."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("exposure_check", ROOT / "scripts/exposure_check.py")
exposure_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exposure_check)


def test_snapshot_keeps_only_comparable_fields_with_sorted_ports():
    host = {"ip_str": "198.51.100.20", "ports": [443, 22], "org": "Example ISP",
            "last_update": "2026-11-01T08:00:00.000000", "data": [{"banner": "noise"}]}
    assert exposure_check.snapshot(host) == {
        "ip": "198.51.100.20", "ports": [22, 443], "org": "Example ISP",
        "last_update": "2026-11-01T08:00:00.000000",
    }
```

```bash
make test
set -a; . ./.env.secrets; set +a
python3 scripts/exposure_check.py
```

Run it once. A loop burns through the free tier in minutes. If Shodan answers that no
information is available, nothing on that address has been indexed, and that is a valid
finding: record it. Either way, the snapshot in `exposure/` is the baseline Lab 7 diffs
against to alert you on a new open port.

## Going further (optional): GeoIP and ASN

Create a free MaxMind account, download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`,
put them in a git-ignored `geoip/` folder and mount it into Logstash at `/geoip`. Then
add two filters after the translate block:

```
    geoip { source => "[destination][ip]" target => "destination"
            database => "/geoip/GeoLite2-City.mmdb" tag_on_failure => [] }
    geoip { source => "[destination][ip]" target => "destination"
            database => "/geoip/GeoLite2-ASN.mmdb" tag_on_failure => [] }
```

Private addresses have no location, so `tag_on_failure => []` keeps them free of noise
tags. Check the resulting `destination.geo` and `destination.as` fields in Discover
before you rely on the names.

## Check your work

Before you open the pull request, every line here must hold:

- [ ] `make test` passes with nothing skipped, Lab 5 tests included.
- [ ] `git status` lists nothing under `enrich/`, `exposure/` or `data/`, and no plaintext key.
- [ ] `git log -p` shows the MISP and Shodan keys only as `ENC[...]`.
- [ ] `docs/misp-setup.md` names the feed, the fetch date and the image digests.
- [ ] Discover shows the bad record tagged and scored, and the clean one untouched, with both screenshots in `docs/evidence/`.
- [ ] No screenshot or commit shows your public IP or an AMBER indicator.
- [ ] Your commits and the pull request description mention R-04 and R-05.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| MISP will not start: port 443 or 80 is already allocated | Part A step 2 was skipped. Set `NGINX_HTTPS_PORT` and `NGINX_HTTP_PORT`, then `docker compose up -d` again. |
| MISP pages load but links point to `localhost` without the port | `BASE_URL` lacks `:8444`. Fix it in `misp-docker/.env` and recreate the containers. |
| `misp_pull.py` fails with an SSL error | MISP uses a self-signed certificate. Leave `MISP_CA` empty in this lab, or point it at the certificate file. |
| `misp_pull.py` says MISP returned no indicators | The feed was not fetched, or nothing flagged `to_ids` changed within 30 days. Check the feed first, then try `MISP_MAX_AGE=180d`. |
| Every pipeline test fails after you add `translate` | The tests do not mount a dictionary. Add the `ioc_ip_test.yml` mount from Part D step 2. |
| Logstash in the stack fails on `dictionary_path` | `enrich/ioc_ip.yml` does not exist yet, or `./enrich` is not mounted. Run `misp_pull.py`, check the volume, then `make up`. |
| A new indicator does not tag anything | The dictionary reloads every 300 seconds. Wait, or restart Logstash. |
| An IP you know is in MISP never matches | The MISP attribute is a CIDR range. `translate` matches exact values only. |
| Shodan returns 401 or a rate-limit error | Check `SHODAN_KEY` in `.env.secrets`. The free tier allows a single call per run. |
