# Lab 4: CI/CD Validation and Supply-Chain Security

You will build a GitHub Actions pipeline that refuses to merge or ship anything
unchecked. It lints, tests and scans every pull request, and on a tag it builds, signs
and releases the front door image from Lab 3 with a software bill of materials (SBOM).
Then you will harden the pipeline itself, because a CI system that runs other people's
code with your token is a supply-chain target in its own right.

This lab closes **R-08** (a third-party action's tag is moved to malicious code) and
**R-09** (a fork pull request reads repository secrets) from the course register, and
it turns the required checks behind **R-01** into something real. Reference them in
your commits and in your pull request.

## What you need

- Lab 3 merged in your repository: `compose.yaml`, `nginx/frontdoor.conf`, the Makefile
- Your declared GitHub route (ULBS organisation, Education, Pro or Free). Part E depends on it.
- The GitHub CLI, logged in (`gh auth status`)
- Docker, plus `cosign`, `syft` and `trivy` on your machine (`brew install cosign syft trivy`)

Work on a branch:

```bash
git switch main && git pull --ff-only
git switch -c lab4/cicd
```

## Part A: Give the pipeline something to build and test

### 1. Turn the front door into an image

The pipeline scans and signs an image, so the Lab 3 front door needs a Dockerfile.
Create `nginx/Dockerfile`:

```dockerfile
# Front door from Lab 3: nginx terminates TLS in front of OpenSearch Dashboards.
# Pinned by tag and digest, so the build never floats.
FROM nginx:1.27-alpine@sha256:REPLACE_WITH_DIGEST

# Site config only. Certificates stay out of the image and are mounted at runtime
# from certs/ (git-ignored), exactly as in compose.yaml.
COPY frontdoor.conf /etc/nginx/conf.d/default.conf

EXPOSE 443
```

Fill in the digest and check the base image before you build on it:

```bash
docker pull nginx:1.27-alpine
D=$(docker inspect --format '{{index .RepoDigests 0}}' nginx:1.27-alpine | cut -d@ -f2)
sed -i '' "s|sha256:REPLACE_WITH_DIGEST|$D|" nginx/Dockerfile   # Linux: sed -i "s|...|...|"
trivy image --severity HIGH,CRITICAL --exit-code 1 nginx:1.27-alpine
```

If Trivy reports HIGH or CRITICAL findings, your clean baseline is not clean. Move to a
newer tag (check the `stable-alpine` line on Docker Hub), pin its digest, and update
`compose.yaml` to the same digest.

Certificates never go into the image. A pushed, signed image is public evidence, and a
key inside it would be a leak you signed yourself.

### 2. Pin the test dependencies

Create `requirements-dev.txt`:

```
# Test dependencies for the CI "test" job and `make test`.
# Pinned exactly so every run installs the same version.
pytest==9.2.0
PyYAML==6.0.3
```

### 3. Test that nothing floats

A pipeline needs at least one real test, or pytest exits with "no tests ran" and the job
fails. Start with one that guards the supply chain directly. Create
`tests/test_pinning.py`:

```python
"""Every image this repo builds or runs is pinned by digest (RISK-REGISTER: supply chain).

A floating tag such as nginx:1.27-alpine can change under you between two builds.
A digest cannot. Images that come from .env (${VAR}) are pinned there instead.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def dockerfiles():
    return sorted(p for p in ROOT.rglob("Dockerfile*") if ".git" not in p.parts)


@pytest.mark.parametrize("path", dockerfiles(), ids=lambda p: str(p.relative_to(ROOT)))
def test_dockerfile_base_images_are_pinned_by_digest(path):
    froms = [line.split()[1] for line in path.read_text().splitlines()
             if line.strip().upper().startswith("FROM ")]
    assert froms, f"{path} has no FROM line"
    for image in froms:
        assert DIGEST.search(image), f"{path}: {image} is not pinned by a real digest"


def test_compose_images_are_pinned_by_digest_or_come_from_env():
    compose = ROOT / "compose.yaml"
    if not compose.exists():
        pytest.skip("no compose.yaml in this repository")
    services = yaml.safe_load(compose.read_text()).get("services", {})
    for name, svc in services.items():
        image = svc.get("image", "")
        if not image or image.startswith("${"):
            continue
        assert DIGEST.search(image), f"service {name}: {image} is not pinned by digest"
```

The test also catches a digest placeholder that someone forgot to fill in, which
Hadolint does not.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python3 -m pytest -q
```

Add a `test` target to the Makefile if Lab 3 did not give you one.

## Part B: Pin every action to a commit SHA

`uses: actions/checkout@v4` does not name code. It names a tag, and whoever controls the
action's repository can move that tag to any commit, at any time. Your next run then
executes the new code with your token and your secrets. Real attacks have done exactly
that to popular actions and swept secrets out of thousands of repositories. A full
40-character commit SHA cannot be moved.

### 1. Resolve the SHAs

`git ls-remote` needs no login. The `^{}` entry, when present, is the commit behind an
annotated tag, and that is the one to pin:

```bash
for a in actions/checkout@v4.2.2 ludeeus/action-shellcheck@2.0.0 \
         hadolint/hadolint-action@v3.1.0 actions/setup-python@v5.6.0 \
         aquasecurity/trivy-action@v0.28.0 docker/login-action@v3.4.0 \
         anchore/sbom-action@v0.20.0 sigstore/cosign-installer@v3.8.2; do
  r=${a%@*}; t=${a#*@}
  sha=$(git ls-remote "https://github.com/$r.git" "refs/tags/$t^{}" "refs/tags/$t" | head -1 | cut -f1)
  echo "uses: $r@$sha # $t"
done
```

Compare the output with the SHAs in the workflow below. If a tag has moved since this
guide was written, find out why before you trust the new commit. That habit is the
control. Tags can also disappear: `trivy-action` once published `0.28.0`, and today only
`v0.28.0` exists.

### 2. Write the workflow

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on:
  pull_request:
    branches: [main]
  push:
    tags: ['v*']

# The default token is read-only. Only the release job widens it.
permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      # Every third-party action is pinned to a full commit SHA; the tag is only a comment.
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: ludeeus/action-shellcheck@00cae500b08a931fb5698e11e79bfbd38e612a38 # 2.0.0
      - uses: hadolint/hadolint-action@54c9adbab1582c2ef04b2016b760714a4bfde3cf # v3.1.0
        with:
          dockerfile: nginx/Dockerfile
      - name: Semgrep
        run: pip install semgrep==1.184.0 && semgrep scan --config p/ci --error
      - name: zizmor (the pipeline audits itself)
        run: pip install zizmor==1.32.0 && zizmor --offline .

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: '3.11'
      - run: pip install -r requirements-dev.txt && pytest -q

  scan:
    runs-on: ubuntu-latest
    needs: [lint]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - run: docker build -t frontdoor:ci nginx/
      - uses: aquasecurity/trivy-action@915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2 # v0.28.0
        with:
          image-ref: frontdoor:ci
          severity: HIGH,CRITICAL
          exit-code: '1'

  release:
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    needs: [lint, test, scan]
    permissions:
      contents: write   # create the release
      packages: write   # push the image to GHCR
      id-token: write   # OIDC identity for keyless signing
    env:
      IMG: ghcr.io/${{ github.repository }}/frontdoor:${{ github.ref_name }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: docker/login-action@74a5d142397b4f367a81961eba4e8cd7edddf772 # v3.4.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - run: docker build -t "$IMG" nginx/ && docker push "$IMG"
      - uses: anchore/sbom-action@e11c554f704a0b820cbf8c51673f6945e0731532 # v0.20.0
        with:
          image: ${{ env.IMG }}
          format: spdx-json
          output-file: sbom.spdx.json
      - uses: sigstore/cosign-installer@3454372f43399081ed03b604cb2d021dabca52bb # v3.8.2
      - run: cosign sign --yes "$IMG"
      - name: Release with generated notes and the SBOM
        env:
          GH_TOKEN: ${{ github.token }}
        run: >
          gh release create "$GITHUB_REF_NAME" sbom.spdx.json
          --repo "$GITHUB_REPOSITORY" --verify-tag --generate-notes
```

A few choices here are deliberate, and you will be asked to defend them:

- `persist-credentials: false` stops checkout from leaving the token in `.git/config`,
  where a later step or an uploaded artifact could pick it up.
- The release uses the `gh` CLI that ships on the runner, not one more third-party action.
  Every action you avoid is one less thing that can be compromised.
- Semgrep and zizmor are installed at exact versions. An unpinned `pip install` is the
  same problem as an unpinned action.
- `${{ ... }}` expressions never appear inside `run:` scripts. Values reach the shell
  through `env:`, so a crafted branch or tag name cannot inject commands.

### 3. Map every job to a risk

Add this table to your project document, adjusted to your own register IDs:

| Job | What it blocks | Risk |
|---|---|---|
| `lint` / ShellCheck, Hadolint | Broken scripts and unsafe Dockerfile patterns | Build integrity |
| `lint` / Semgrep | Known insecure code patterns | Application flaws |
| `lint` / zizmor | Unpinned actions, leaked credentials, risky triggers in the pipeline itself | R-08, R-09 |
| `test` | Floating image tags, broken logic | Supply chain, R-03 later |
| `scan` / Trivy | Images with HIGH or CRITICAL vulnerabilities | Vulnerable image |
| `release` / Syft, Cosign | Unsigned or undocumented artefacts reaching users | Tampered image |

If your register has no row for a vulnerable or tampered container image, add one now
with its likelihood, impact and these jobs as the control.

## Part C: Lock down the Actions settings

Open the repository on GitHub, then Settings, Actions, General. Screenshot each section
after you change it, for `docs/evidence/`.

1. **Actions permissions.** Tick "Require actions to be pinned to a full-length commit
   SHA". From now on, GitHub itself refuses to run a workflow that uses a tag.
2. **Workflow permissions.** Choose "Read repository contents and packages permissions"
   and untick "Allow GitHub Actions to create and approve pull requests". The workflow's
   `permissions:` blocks then widen access per job, never the other way round.
3. **Fork pull request workflows.** On a private repository, leave "Run workflows from
   fork pull requests" off unless you need it. If you turn it on, keep "Send secrets and
   variables" and "Send write tokens" off, and tick "Require approval for fork pull
   request workflows". On a public repository, set approval to "Require approval for all
   external contributors".
4. **Triggers.** Never use `pull_request_target` together with a checkout of the pull
   request's code. That trigger runs with your secrets, and zizmor fails the lint job
   if you try.

These settings close R-09: an outside pull request cannot reach your secrets without a
maintainer's explicit approval.

## Part D: Keep the pins fresh, but not too fresh

Pinned SHAs go stale, and stale pins miss security fixes. Dependabot proposes updates
as pull requests that go through the same pipeline. The cooldown holds every new release
back for seven days, because a compromised release is usually caught and pulled within
days. Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
  - package-ecosystem: docker
    directory: /nginx
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
```

Dependabot updates the SHA and the tag comment together, and it bumps the digest in
`nginx/Dockerfile` too. zizmor checks this file as well, and it fails the lint job if
the cooldown goes missing.

## Part E: Open the pull request and make the checks required

### 1. Push and watch

```bash
git add nginx/Dockerfile requirements-dev.txt tests/test_pinning.py \
        .github/workflows/ci.yml .github/dependabot.yml Makefile
git commit -m "ci: pinned pipeline with scan, SBOM, signing and release (R-01, R-08, R-09)"
git push -u origin lab4/cicd
gh pr create --base main --fill
gh pr checks --watch
```

Stage files by name. `git add -A` is how a stray `.env` reaches a public repository.

### 2. Require the checks

Checks show up in the ruleset picker only after they have run once, so do this while
the pull request is green.

- **ULBS organisation, Education with Pro, or Pro:** Settings, Rules, Rulesets, open
  your `main` ruleset and require the status checks `lint`, `test` and `scan`, plus
  "Require branches to be up to date". Export the result as evidence:
  `gh api repos/{owner}/{repo}/rulesets --jq '.[].id'`, then
  `gh api repos/{owner}/{repo}/rulesets/<id> > docs/ruleset-main.json`.
- **GitHub Free:** a private repository cannot enforce required checks. Your governance
  workflow from Lab 1 proves that every commit on `main` arrived through a merged pull
  request. Add one line to your project document stating that you never merge a red
  pull request, then make the history prove it.

Merge the pull request once it is green.

## Part F: Prove the gates close

A control you have not seen fail is a control you hope works. Open each of these as its
own pull request, screenshot the failure, then close it without merging.

### 1. A vulnerable base image fails the scan

```bash
git switch main && git pull --ff-only && git switch -c demo/vulnerable-base
docker pull python:3.9-slim
trivy image --severity HIGH,CRITICAL python:3.9-slim | tail -5
```

If Trivy shows HIGH findings, pin that image's digest as the `FROM` line in
`nginx/Dockerfile`, commit, push and open the pull request. `scan` goes red, and on a
paid route the merge button greys out. Pick any old image that Trivy flags if
`python:3.9-slim` happens to come back clean.

### 2. An unpinned action fails twice

```bash
git switch main && git switch -c demo/unpinned-action
```

Change the Hadolint line to `uses: hadolint/hadolint-action@v3.1.0`, commit, push and
open the pull request. GitHub refuses to start the run because of the pinning policy
from Part C. If you cannot enable that policy on your plan, zizmor still fails `lint`
with `unpinned-uses`. Either way, the moving tag never runs.

## Part G: Release, sign and verify

### 1. Cut the release

```bash
git switch main && git pull --ff-only
git tag v0.4.0 && git push origin v0.4.0
gh run watch
```

While it runs, be ready to explain keyless signing. The workflow's OIDC token proves
which repository and workflow is running. Sigstore's Fulcio issues a certificate valid
for a few minutes, bound to that identity. The signature is recorded in Rekor, a public
transparency log. No long-lived signing key exists to steal.

**Private repositories, read this.** Rekor is public. Signing from a private repository
publishes your repository and workflow name in that log for good. Decide whether that is
acceptable for your project and record the decision in your register. If it is not,
sign with a key pair (`cosign generate-key-pair`, private key stored as an encrypted
Actions secret) and say why.

### 2. Verify from your own machine

Your GHCR package is private, so log in first. Add the `read:packages` scope to your
GitHub CLI login once, then pipe the token in, so it never appears in your shell history:

```bash
gh auth refresh -s read:packages
gh auth token | docker login ghcr.io -u <your-user> --password-stdin
IMG=ghcr.io/<your-user>/<your-repo>/frontdoor:v0.4.0

cosign verify "$IMG" \
  --certificate-identity-regexp "^https://github.com/<your-user>/<your-repo>/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
syft "$IMG" -o table | head -20
gh release view v0.4.0
```

`cosign verify` must print the certificate identity of your workflow. A signature from
any other repository fails this command, and that is the whole point. Save the three
outputs as evidence.

## Going further (optional): watch a tag move

In your own account only, fork any small action, reference it from a throwaway
repository's workflow as `@v1`, then move `v1` in your fork to a commit that just prints
a marker. The next run picks up the new code with no change on the consumer side. Pin
the reference to the original SHA and the moved tag no longer runs. Never do this to an
action or repository you do not own.

## Check your work

Before you open the pull request, every line here must hold:

- [ ] Every `uses:` line is a 40-character SHA with the tag in a trailing comment.
- [ ] zizmor reports no findings: `pip install zizmor==1.32.0 && zizmor --offline .`
- [ ] `python3 -m pytest -q` passes and the Dockerfile `FROM` line carries a real digest.
- [ ] The workflow's top-level `permissions:` is read-only and only `release` widens it.
- [ ] Settings screenshots show the pinning policy, read-only token and fork settings.
- [ ] Both failure pull requests from Part F are closed unmerged, with screenshots.
- [ ] `cosign verify` succeeds for `v0.4.0` and the release carries `sbom.spdx.json`.
- [ ] Your register records the signing decision and your commits mention R-01, R-08 and R-09.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| The run fails before any job with a message about full-length commit SHAs | The pinning policy works. Pin the action named in the error. |
| `gh api .../commits/0.28.0` returns 422 | The tag no longer exists. List what does with `git ls-remote --tags https://github.com/<owner>/<repo>.git`. |
| `docker build` fails with `invalid reference format` | The `FROM` line still says `REPLACE_WITH_DIGEST`. Fill it in (Part A step 1). `test_pinning.py` catches this too. |
| `test` fails with "no tests ran" | pytest found nothing to collect. Check that `tests/test_pinning.py` is committed. |
| `scan` is red on a clean pull request | The base image has HIGH or CRITICAL CVEs today. Move to a newer tag and pin its digest. |
| zizmor reports `artipacked` | A checkout step lacks `persist-credentials: false`. |
| zizmor reports `dependabot-cooldown` | An entry in `.github/dependabot.yml` has no `cooldown`. |
| `release` cannot push to GHCR | The job lacks `packages: write`, or the package belongs to another repository. Check the package's Actions access settings. |
| `cosign sign` cannot get an OIDC token | The job lacks `id-token: write`. |
| `gh release create` says the tag was not found | `--verify-tag` needs the tag pushed. Run `git push origin v0.4.0`. |
| `cosign verify` finds no matching signatures | The identity regex does not match your repository URL exactly, or you are not logged in to GHCR. |
| `lint`, `test` and `scan` are missing from the ruleset picker | They have not run yet. Open the pull request first, then add them. |
