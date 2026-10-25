# Lab 3: IaaS

You will build a small OpenSearch stack as code on your own machine. Images are pinned by
digest, the admin password lives in git only as ciphertext, `make` decrypts it at deploy
time, and an nginx front door serves TLS from a lab certificate authority you create.

This lab closes risk **R-02** (plaintext secrets in the repository). Reference it in your
commits and in your pull request.

## What you need

- Docker with Compose v2.17 or newer (`docker compose version`)
- Git and your clone of `secops-demo`
- Homebrew on macOS, or the release binaries on Linux
- A terminal you can keep open for the CA server in Part C

Work on a branch. `main` only accepts pull requests (R-01).

```bash
git switch -c lab3/iaas
```

## Part A: Prepare your machine

1. Pull the images and record their digests. You will paste them into `compose.yaml`, so
   keep them in your notes.

   ```bash
   docker pull opensearchproject/opensearch:2.19.1
   docker pull opensearchproject/opensearch-dashboards:2.19.1
   docker pull nginx:1.27-alpine
   docker images --digests | grep -E "opensearch|nginx"
   ```

   To get one digest in the exact form compose needs:

   ```bash
   docker inspect --format '{{index .RepoDigests 0}}' opensearchproject/opensearch:2.19.1
   # opensearchproject/opensearch@sha256:...
   ```

2. Install `sops`, `age` and `step` (the smallstep CLI, which also ships `step-ca`):

   ```bash
   brew install sops age step
   sops --version   # needs 3.9 or newer
   ```

   On Linux, download the release binaries from each project's GitHub releases page.

3. Generate your own age key and tell sops where to find it. The output prints your public
   key (`age1...`). Copy it into your notes.

   ```bash
   mkdir -p ~/.config/sops/age
   age-keygen -o ~/.config/sops/age/keys.txt
   chmod 600 ~/.config/sops/age/keys.txt
   echo 'export SOPS_AGE_KEY_FILE=$HOME/.config/sops/age/keys.txt' >> ~/.zshrc   # or ~/.bashrc
   source ~/.zshrc
   ```

   `keys.txt` holds your private key. It stays in your home directory and never goes into
   the repository. If you lose it, you cannot decrypt your own secrets.

4. On Linux hosts, raise the memory map limit or OpenSearch will not start:

   ```bash
   sudo sysctl -w vm.max_map_count=262144
   echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf
   ```

   Docker Desktop on macOS already sets this inside its VM.

## Part B: Build the stack

### 1. Put the ports in `.env`

The project rule is that no port or hostname is hardcoded. Create `.env` in the repo root:

```bash
OPENSEARCH_PORT=9200
DASHBOARDS_PORT=5601
HTTPS_PORT=443
```

### 2. Generate `compose.yaml` with the assistant

Open the assistant in the repo so it reads `CLAUDE.md`, then ask for the file. Paste your
own digests into the prompt:

> Generate compose.yaml for a single-node OpenSearch 2.19.1 cluster plus OpenSearch
> Dashboards 2.19.1. Pin both images by digest: `<opensearch digest>`,
> `<dashboards digest>`. Read every host port from .env (OPENSEARCH_PORT,
> DASHBOARDS_PORT). Pass OPENSEARCH_INITIAL_ADMIN_PASSWORD into the opensearch container
> from the environment and never write a password into the file. Use a named volume for
> data.

Do not accept the output as is. Review it against this list and fix what fails:

- [ ] Every `image:` line uses `@sha256:` with the digests you recorded. Replace any
      floating tag (`:latest`, `:2`, `:2.19.1` alone) the assistant slipped in.
- [ ] Host ports appear only as `${OPENSEARCH_PORT}` and `${DASHBOARDS_PORT}`.
- [ ] `discovery.type=single-node` is set on OpenSearch.
- [ ] The admin password appears only as `${OPENSEARCH_INITIAL_ADMIN_PASSWORD}`.
- [ ] Data sits on a named volume, so `make down` (which runs `down -v`) gives you a clean
      start.

### 3. Encrypt the admin password with sops

First write `.sops.yaml`. The heredoc fills in your public key from `keys.txt`:

```bash
cat > .sops.yaml <<EOF
creation_rules:
  - path_regex: secrets/.*\.enc\.yaml$
    age: $(grep -o 'age1[0-9a-z]*' ~/.config/sops/age/keys.txt)
EOF
cat .sops.yaml   # check that age: holds your age1... key
```

Choose your own admin password. OpenSearch rejects weak ones, so use at least 12
characters with upper and lower case, digits and a symbol from `!@%^*-_+=`. Avoid `$`,
`#`, quotes, spaces and colons, because they break the YAML or the env file later.

The commands below read the password without echoing it and without saving it in your
shell history. `--filename-override` tells sops which creation rule to apply, since the
input comes from stdin.

```bash
mkdir -p secrets
printf 'Admin password: '; read -rs OS_PW; echo
printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD: %s\n' "$OS_PW" \
  | sops --encrypt --filename-override secrets/opensearch.enc.yaml \
      --input-type yaml --output-type yaml /dev/stdin > secrets/opensearch.enc.yaml
unset OS_PW
```

Commit it and look at what git actually stores:

```bash
git add .sops.yaml secrets/opensearch.enc.yaml
git commit -m "feat: encrypted admin secret (R-02)"
git show HEAD:secrets/opensearch.enc.yaml | head
```

You should see `ENC[AES256_GCM,data:...]` in place of the password and a `sops:` block
listing your age recipient. That is the only form of the secret that ever reaches git
history. The private key that can open it stays in `~/.config/sops/age/keys.txt`.

### 4. Decrypt at deploy time with `make`

Add the decrypted file to `.gitignore` **before** you run anything, together with the
certificate folder from Part C:

```bash
printf '.env.secrets\ncerts/\n' >> .gitignore
```

Create the `Makefile`. Recipe lines must start with a tab, not spaces.

```makefile
.PHONY: up down test lint secrets

secrets:
	sops -d secrets/opensearch.enc.yaml | sed 's/: /=/' > .env.secrets

up: secrets
	docker compose --env-file .env --env-file .env.secrets up -d

down:
	docker compose down -v && rm -f .env.secrets
```

`make secrets` turns the YAML line into `OPENSEARCH_INITIAL_ADMIN_PASSWORD=...`, which
compose reads as a second env file. The plaintext exists only while the stack runs, and
`make down` deletes it.

### 5. Prove the deploy is repeatable

```bash
make up
```

OpenSearch needs about a minute. Poll the health endpoint with your own password:

```bash
curl -ku 'admin:<your password>' "https://localhost:${OPENSEARCH_PORT:-9200}/_cluster/health?pretty"
```

Wait for `"status" : "green"`. Yellow on a single node means a replica has nowhere to go
and is acceptable here. Red, or a connection error after two minutes, means something is
wrong (see Troubleshooting).

Then tear it all down and build it again from nothing:

```bash
make down
make up
# poll health again until green
```

The second run must reach the same state with no manual fixes. Save both health outputs:
that is your proof of idempotence, shown rather than claimed.

## Part C: A lab PKI in front of Dashboards

### 1. Create the CA and start it

```bash
step ca init --name "Lab Root" --dns localhost --address :8443 \
  --provisioner admin --deployment-type standalone
```

`step` asks for a password that protects the CA keys. Remember it. Everything lands in
`$(step path)` (usually `~/.step`), outside the repository.

Start the CA in a second terminal and leave it running:

```bash
step-ca $(step path)/config/ca.json
```

### 2. Issue the front door certificate

Back in the first terminal:

```bash
mkdir -p certs
step ca certificate frontdoor.lab certs/frontdoor.crt certs/frontdoor.key \
  --san frontdoor.lab --san localhost \
  --ca-url https://localhost:8443 --root $(step path)/certs/root_ca.crt
```

The extra `--san localhost` lets the browser accept the certificate at
`https://localhost`. `frontdoor.crt` contains the leaf and the intermediate, so nginx can
serve the full chain. The default lifetime is 24 hours; issue a new one when it expires.

### 3. Add nginx to the stack

Create `nginx/frontdoor.conf`. Match the upstream name to the Dashboards service name in
your `compose.yaml`:

```nginx
server {
    listen 443 ssl;
    server_name localhost frontdoor.lab;

    ssl_certificate     /etc/nginx/certs/frontdoor.crt;
    ssl_certificate_key /etc/nginx/certs/frontdoor.key;

    location / {
        proxy_pass http://opensearch-dashboards:5601;
        proxy_set_header Host $host;
    }
}
```

Add the service to `compose.yaml`, pinned by the nginx digest you recorded:

```yaml
  frontdoor:
    image: nginx@sha256:<your nginx digest>
    ports:
      - "${HTTPS_PORT}:443"
    volumes:
      - ./nginx/frontdoor.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs/frontdoor.crt:/etc/nginx/certs/frontdoor.crt:ro
      - ./certs/frontdoor.key:/etc/nginx/certs/frontdoor.key:ro
    depends_on:
      - opensearch-dashboards
```

Run `make up` to create it. After you renew the certificate later, reload nginx without a
restart:

```bash
docker compose exec frontdoor nginx -s reload
```

### 4. Trust the root and inspect the chain

Install the lab root into your system trust store, then open `https://localhost` (add
`:<HTTPS_PORT>` if you changed it):

```bash
step certificate install $(step path)/certs/root_ca.crt
```

Click the padlock and view the certificate. You should see three levels:
`frontdoor.lab`, then `Lab Root Intermediate CA`, then `Lab Root Root CA`. The same check
from the terminal:

```bash
openssl s_client -connect localhost:443 -showcerts </dev/null | grep -E "s:|i:"
```

`root_ca.crt` is now the single trust anchor. Every service you add in later labs gets
its certificate from this CA, and every client trusts only this one file. Firefox keeps
its own store, so import the root there by hand if you use it. Remove the root at the end
of the course with `step certificate uninstall $(step path)/certs/root_ca.crt`.

## Check your work

Before you open the pull request, every line here must hold:

- [ ] `compose.yaml` has no floating tags and no hardcoded host ports.
- [ ] `git log -p` shows the password only as `ENC[...]`.
- [ ] `git status` does not list `.env.secrets`, `certs/` or any key file.
- [ ] `make down && make up` reaches green twice in a row.
- [ ] The browser shows the `frontdoor.lab` chain ending at `Lab Root Root CA`.
- [ ] Your commits and the pull request description mention R-02.

Put the evidence (both health outputs, the `git show` ciphertext and a screenshot of the
certificate chain) in `docs/evidence/`, push the branch and open the pull request.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| OpenSearch exits with `max virtual memory areas vm.max_map_count [65530] is too low` | Part A step 4 was skipped on Linux. Set the sysctl and run `make up` again. |
| `sops: error loading config: no matching creation rules found` | You ran sops from the wrong folder or left out `--filename-override`. Run it from the repo root. |
| `make secrets` fails with `failed to get the data key` | sops cannot find your private key. Check that `echo $SOPS_AGE_KEY_FILE` points to `keys.txt`. |
| OpenSearch logs mention a weak or invalid admin password | Encrypt a stronger password (Part B step 3) and commit the new file. |
| `step ca certificate` cannot connect to `localhost:8443` | The CA is not running. Start `step-ca` in the second terminal. |
| Browser warns about the certificate after installing the root | Restart the browser, and check that the certificate includes `localhost` as a SAN. |
