---
name: shor-setup
description: >
  Full interactive setup guide for Shor (the web-security scanning platform).
  Invoke when a user wants to pentest a target: guides scan-type selection,
  repo analysis, compute recommendation, pre-flight, deployment, auth wiring,
  and Shor project + scan creation. Also covers deploying the Shor platform
  itself on GCP when it is not yet running. Handles black-box and white-box modes.
metadata:
  type: setup-guide
  version: "1.2.0"
---

# Shor Setup — Interactive Pentest Wizard

**What this skill does**: walks from zero to a running Shor scan in one session.
Ask ONLY the questions listed in each phase — no extras, no confirmation loops.
Execute every command silently and report results, not intentions.

**First**: check if Shor is already deployed:

```bash
gcloud run services describe shor-web --region us-central1 --project shor-x-sinas \
  --format "value(status.url)" 2>/dev/null
```

- **URL returned** → Shor is live. Skip to **Phase 1** (scan setup).
- **Nothing / error** → Shor needs to be deployed first. Work through **Part A** below, then come back to Phase 1.

---

# Part A — Deploy Shor on GCP

Only needed when Shor is not yet running. This is a one-time setup.

---

## A1 — GCP project + APIs

```bash
PROJECT=shor-x-sinas
REGION=us-central1

# Create project (skip if it already exists)
gcloud projects create $PROJECT --name="Shor"
gcloud config set project $PROJECT

# Link billing account (required for Cloud Run, Artifact Registry, etc.)
gcloud billing projects link $PROJECT \
  --billing-account=$(gcloud billing accounts list --format="value(name)" | head -1)

# Enable all APIs Shor needs in one call
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com \
  iam.googleapis.com \
  --project=$PROJECT
```

## A2 — Artifact Registry + GCS bucket

```bash
# Docker image registry
gcloud artifacts repositories create shor \
  --repository-format=docker \
  --location=$REGION \
  --project=$PROJECT

# Authenticate Docker to the registry
gcloud auth configure-docker ${REGION}-docker.pkg.dev

# GCS bucket for repo staging (white-box scans stage cloned repos here)
gsutil mb -p $PROJECT -l $REGION gs://${PROJECT}-shor
```

Image paths (used throughout):
- **Base** : `${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-worker-base:latest`
- **Worker**: `${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-scan-worker:latest`
- **Web**  : `${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-web:latest`

## A3 — Secret Manager: create all secrets

Run this block — it creates the secrets as empty placeholders, then you fill each value:

```bash
# Helper: create a secret and set its value in one step
mksecret() { name="$1"; val="$2"
  gcloud secrets create "$name" --project=$PROJECT --replication-policy=automatic 2>/dev/null || true
  printf '%s' "$val" | gcloud secrets versions add "$name" --data-file=- --project=$PROJECT
}

# ── Shared service tokens ────────────────────────────────────────────────────
mksecret shor-sink-token          "$(openssl rand -hex 32)"   # worker→web findings POST
mksecret shor-engine-trigger-token "$(openssl rand -hex 24)"  # /external/* bearer
mksecret shor-session-secret      "$(openssl rand -hex 32)"   # cookie signing

# ── Dashboard gate passcode (locks the whole UI) ────────────────────────────
mksecret shor-app-passcode        "$(openssl rand -base64 16 | tr -d '=+/')"

# ── Database ─────────────────────────────────────────────────────────────────
# Use Supabase (see A4). Paste the Supabase postgres password here:
mksecret shor-supabase-db-pass    "<supabase-postgres-password>"

# ── AI provider key (the engine that runs the agents) ───────────────────────
# Shor uses DeepSeek by default (cheap, fast). Paste your DeepSeek API key:
mksecret shor-deepseek-key        "<your-deepseek-api-key>"
# Or use Anthropic:   mksecret shor-anthropic-key "<your-anthropic-api-key>"

# ── GitHub App (for cloning private repos in white-box mode) ────────────────
# Created in A5 — fill in after creating the App.
mksecret shor-github-app-private-key  "<github-app-pem>"
```

Retrieve any secret later:

```bash
gcloud secrets versions access latest --secret=<name> --project=$PROJECT
```

## A4 — Database: Supabase

Shor uses Supabase Postgres (avoids Cloud SQL billing risk on GCP account suspension).

1. Go to [supabase.com](https://supabase.com) → **New project** → choose any region.
2. Copy the **postgres password** at creation time (not shown again) → add to `shor-supabase-db-pass`.
3. From **Project Settings → Database**, copy the **Session pooler** connection string.
   The connection string uses the session-pooler host on port 5432 with user `postgres.<ref>`.
4. Record these values:

```
SUPABASE_HOST=aws-0-<region>.pooler.supabase.com
SUPABASE_PORT=5432
SUPABASE_USER=postgres.<project-ref>
SUPABASE_DB=postgres
```

## A5 — GitHub App (white-box repo access)

Only needed if users will scan private repos.

1. Go to **github.com/settings/apps → New GitHub App**.
2. Name: `Shor Scanner` (or similar).
3. Homepage URL: your Shor URL (fill in after A9).
4. Callback URL: `<SHOR_URL>/auth/github/callback`.
5. **Permissions**: `Contents: Read-only`, `Metadata: Read-only`.
6. **Subscribe to events**: none required.
7. Generate a **private key** → download the `.pem` → add to `shor-github-app-private-key` secret.
8. Note the **App ID** and **Client ID** and **Client Secret** → needed for A8 env vars.

## A6 — Service accounts

The worker needs a per-tenant service account to access only its own secrets.
For the first (and only) tenant this is the pattern:

```bash
TENANT_ID="1"   # the numeric tenant ID minted by the DB

# Worker run identity — one per tenant
gcloud iam service-accounts create shor-scan-${TENANT_ID} \
  --display-name="Shor scan worker (tenant ${TENANT_ID})" \
  --project=$PROJECT

# Grant it access to its OWN provider key secret only (set in A7 after first login)
# Pattern: gcloud secrets add-iam-policy-binding <secret-id> \
#   --member="serviceAccount:shor-scan-${TENANT_ID}@${PROJECT}.iam.gserviceaccount.com" \
#   --role="roles/secretmanager.secretAccessor" --project=$PROJECT

# Web service account (reads shared secrets, launches jobs, writes GCS)
gcloud iam service-accounts create shor-web \
  --display-name="Shor web service" --project=$PROJECT

for role in \
  roles/run.invoker \
  roles/secretmanager.secretAccessor \
  roles/storage.objectAdmin \
  roles/run.admin \
  roles/iam.serviceAccountUser; do
  gcloud projects add-iam-policy-binding $PROJECT \
    --member="serviceAccount:shor-web@${PROJECT}.iam.gserviceaccount.com" \
    --role="$role" --quiet
done
```

## A7 — Build the images

> **Two-image split** — Shor's worker is split into a slow **base** (30 offensive
> tools, Chromium, Claude Agent SDK CLI, ~14 min to build) and a fast **app**
> layer (~1–2 min). Rebuild the base only when `tools.lock` / system deps change;
> rebuild the app on every code change.

**Step 1: build the base** (once — takes 20–30 min on Cloud Build E2_HIGHCPU_8):

```bash
gcloud builds submit \
  --config .acceptance/cloudbuild.base.yaml \
  --substitutions _IMAGE=${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-worker-base:latest \
  --project=$PROJECT .
```

The base contains (all compiled against Chainguard Wolfi glibc — NOT Alpine musl):
- **Go tools**: httpx, subfinder, nuclei, dnsx, naabu, katana, ffuf, dalfox, kxss,
  gau, waybackurls, gitleaks, osv-scanner, nosqli, interactsh-client
- **Python venv**: semgrep, arjun, wafw00f, playwright, sqlmap, commix, sstimap,
  xsstrike, ssrfmap, jwt_tool, paramspider
- **Chromium** + all Playwright native deps (libx11, nss, harfbuzz, pango, etc.)
- **Claude Code CLI** (Agent SDK) pinned to a stable version
- Runs as **nonroot uid 65532**, `HOME=/tmp` — the Agent SDK writes its
  skills index to `/tmp/.claude/skills` (pre-created in the image)

**Step 2: build the app + web** (every code change, ~1–2 min each):

```bash
# Worker app (thin layer on the base — Node.js + skills only)
gcloud builds submit \
  --config .acceptance/cloudbuild.yaml \
  --substitutions _IMAGE=${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-scan-worker:latest \
  --project=$PROJECT .

# Dashboard web service
gcloud builds submit \
  --config .acceptance/cloudbuild.web.yaml \
  --substitutions _IMAGE=${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-web:latest \
  --project=$PROJECT .
```

## A8 — Deploy the web service (shor-web)

```bash
SHOR_URL="https://shor-web-<hash>-uc.a.run.app"  # set after first deploy

gcloud run deploy shor-web \
  --image ${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-web:latest \
  --region $REGION \
  --project $PROJECT \
  --service-account shor-web@${PROJECT}.iam.gserviceaccount.com \
  --allow-unauthenticated \
  --set-env-vars "NODE_ENV=production,GCP_PROJECT_ID=${PROJECT},GCP_REGION=${REGION}" \
  --set-env-vars "GCS_BUCKET=${PROJECT}-shor" \
  --set-env-vars "CLOUD_SQL_HOST=<supabase-pooler-host>" \
  --set-env-vars "CLOUD_SQL_PORT=5432" \
  --set-env-vars "CLOUD_SQL_USER=postgres.<supabase-ref>" \
  --set-env-vars "CLOUD_SQL_DATABASE=postgres" \
  --set-env-vars "CLOUD_RUN_WORKER_IMAGE=${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-scan-worker:latest" \
  --set-env-vars "CLOUD_RUN_SCAN_JOB=shor-scan-worker,CLOUD_RUN_SCAN_JOB_HIGHMEM=shor-scan-worker-8gi" \
  --set-secrets "CLOUD_SQL_PASSWORD=shor-supabase-db-pass:latest" \
  --set-secrets "SHOR_SINK_TOKEN=shor-sink-token:latest" \
  --set-secrets "SHOR_ENGINE_TRIGGER_TOKEN=shor-engine-trigger-token:latest" \
  --set-secrets "SHOR_SESSION_SECRET=shor-session-secret:latest" \
  --set-secrets "SHOR_APP_PASSCODE=shor-app-passcode:latest" \
  --set-secrets "GITHUB_APP_PRIVATE_KEY_SECRET_REF=shor-github-app-private-key:latest" \
  --set-env-vars "GITHUB_APP_ID=<github-app-id>" \
  --set-env-vars "GITHUB_OAUTH_CLIENT_ID=<github-oauth-client-id>" \
  --set-secrets "GITHUB_OAUTH_CLIENT_SECRET=<github-oauth-client-secret>:latest" \
  --set-env-vars "SHOR_PUBLIC_URL=<SHOR_URL>" \
  --min-instances 1 \
  --memory 1Gi \
  --cpu 1
```

Get the URL after deploy:

```bash
SHOR_URL=$(gcloud run services describe shor-web \
  --region $REGION --format "value(status.url)")
echo "Shor dashboard: $SHOR_URL"
```

## A9 — Run database migrations

```bash
gcloud run jobs create shor-migrate \
  --image ${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-web:latest \
  --region $REGION \
  --project $PROJECT \
  --service-account shor-web@${PROJECT}.iam.gserviceaccount.com \
  --command "node" \
  --args "apps/web/dist/db/migrate.js" \
  --set-env-vars "CLOUD_SQL_HOST=<supabase-pooler-host>,CLOUD_SQL_PORT=5432" \
  --set-env-vars "CLOUD_SQL_USER=postgres.<ref>,CLOUD_SQL_DATABASE=postgres" \
  --set-secrets "CLOUD_SQL_PASSWORD=shor-supabase-db-pass:latest"

gcloud run jobs execute shor-migrate --region $REGION --project $PROJECT --wait
```

Migrations are in `apps/web/src/db/migrations/`. They are idempotent — safe to re-run.

## A10 — Create the worker Cloud Run Jobs

> **The sandbox**: each scan runs as its own Cloud Run Job execution (not a service).
> The job spec bakes in `executionEnvironment: EXECUTION_ENVIRONMENT_GEN2` — this is
> **required** for the Gen2 sandbox which supports nested processes (headless Chromium,
> offensive CLI tools running inside the container). Gen1 blocks them.
>
> The provider API key is mounted as a **volume file** (never an env var) so it
> cannot leak via `/proc/<pid>/environ`. The job runs as nonroot uid 65532 with
> a writable ephemeral `/work` workdir.

```bash
# Standard worker (4 GB RAM — fits ~90% of targets)
gcloud run jobs create shor-scan-worker \
  --image ${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-scan-worker:latest \
  --region $REGION \
  --project $PROJECT \
  --service-account shor-web@${PROJECT}.iam.gserviceaccount.com \
  --task-timeout 3600 \
  --max-retries 0 \
  --memory 4Gi \
  --cpu 2 \
  --set-env-vars "NODE_ENV=production,GCP_PROJECT_ID=${PROJECT}"

# High-memory worker (8 GB RAM — for large repos, complex SPAs, datanose-class targets)
gcloud run jobs create shor-scan-worker-8gi \
  --image ${REGION}-docker.pkg.dev/${PROJECT}/shor/shor-scan-worker:latest \
  --region $REGION \
  --project $PROJECT \
  --service-account shor-web@${PROJECT}.iam.gserviceaccount.com \
  --task-timeout 3600 \
  --max-retries 0 \
  --memory 8Gi \
  --cpu 4 \
  --set-env-vars "NODE_ENV=production,GCP_PROJECT_ID=${PROJECT}"
```

> **Why two jobs?** Cloud Run does not allow memory overrides per-execution — only
> per-job. A target hostname substring (configurable via `CLOUD_RUN_HIGHMEM_TARGETS`,
> default `datanose`) routes to the 8 Gi job. Everything else hits the 4 Gi job.

## A11 — Add your AI provider key (required to run scans)

After first login to the dashboard, Shor mints a tenant + user record. Find the IDs:

```bash
# Connect to Supabase postgres (use the connection string from A4)
psql "<supabase-connection-string>" \
  -c "SELECT id, name FROM tenants; SELECT id, email FROM users;"
```

Then store the API key the worker will use to call the AI:

```bash
TENANT_ID=<from-db>
USER_ID=<from-db>
PROVIDER=deepseek   # or anthropic, openai

SECRET_ID="shor-${TENANT_ID}-${USER_ID}-${PROVIDER}"
gcloud secrets create $SECRET_ID --project=$PROJECT --replication-policy=automatic
printf '<your-api-key>' | gcloud secrets versions add $SECRET_ID --data-file=- --project=$PROJECT

# Grant the per-run service account access to this secret only
gcloud secrets add-iam-policy-binding $SECRET_ID \
  --member="serviceAccount:shor-scan-${TENANT_ID}@${PROJECT}.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor" --project=$PROJECT
```

## A12 — Verify Shor is working

```bash
SHOR_TOKEN=$(gcloud secrets versions access latest \
  --secret=shor-engine-trigger-token --project=$PROJECT)

# Should return 200 with {projects: []}
curl -s "$SHOR_URL/external/projects" \
  -H "Authorization: Bearer $SHOR_TOKEN" | jq .
```

Open `$SHOR_URL` in a browser → enter the passcode from `shor-app-passcode` →
dashboard loads. **Part A complete — Shor is live.**

---

## Updating Shor after code changes

```bash
# Rebuild app image (worker or web — whichever changed)
gcloud builds submit --config .acceptance/cloudbuild.yaml \
  --substitutions _IMAGE=...shor/shor-scan-worker:latest --project=$PROJECT .
gcloud builds submit --config .acceptance/cloudbuild.web.yaml \
  --substitutions _IMAGE=...shor/shor-web:latest --project=$PROJECT .

# Deploy web (new revision, route 100% traffic)
gcloud run deploy shor-web --image ...shor/shor-web:latest \
  --region $REGION --project $PROJECT

# Update worker jobs (takes effect on next execution)
gcloud run jobs update shor-scan-worker \
  --image ...shor/shor-scan-worker:latest --region $REGION --project $PROJECT
gcloud run jobs update shor-scan-worker-8gi \
  --image ...shor/shor-scan-worker:latest --region $REGION --project $PROJECT
```

**Rebuild the base** only when `infra/docker/Dockerfile.base` or `infra/docker/tools.lock` changes:

```bash
gcloud builds submit --config .acceptance/cloudbuild.base.yaml \
  --substitutions _IMAGE=...shor/shor-worker-base:latest --project=$PROJECT .
# Then rebuild the app image immediately after — it FROM's the base
```

---

---

## Phase 1 — Scan type (ask this first, always)

Send this as your opening message:

> **Black-box or white-box scan?**
>
> - **Black-box** — you have a live URL. Shor probes the running app from the
>   outside, like a real attacker would. Low compute. No source code needed.
> - **White-box** — you have the source code. Shor reads the code AND probes
>   live. Finds significantly more vulnerabilities. Requires a GitHub repo.

Capture the answer, then branch:

- **Black-box** → go to **Phase 2 (black-box)**
- **White-box** → go to **Phase 3 (white-box)**

---

## Phase 2 — Black-box path

### 2a — Target URL

Ask: "What is the target URL? (include scheme — e.g. `https://app.example.com`)"

Validate immediately:

```bash
curl -sf "$TARGET_URL" -o /dev/null \
  && echo "✓ reachable" || echo "✗ unreachable — fix before proceeding"
```

### 2b — Local vs cloud (informed by scan type)

**Black-box is lightweight.** Tell the user:

> "Black-box scans run headless browsers + ~10 agent sessions. On a modern
> laptop (8 GB RAM, 4 cores) this is fine locally. Cloud gives you more
> parallelism and leaves your machine free."

Run the device check silently:

```bash
sysctl hw.memsize | awk '{printf "RAM: %.0f GB\n", $2/1073741824}'
sysctl hw.logicalcpu | awk '{print "CPU cores:", $2}'
docker info --format "Docker: {{.ServerVersion}}" 2>/dev/null || echo "Docker: not running"
```

Show the numbers, then ask:

> "**Local or cloud?** Your machine has [X GB RAM, Y cores, Docker: Z]."

- **Local**: skip gcloud steps; note user needs a Claude API key; use local
  Docker Compose for Shor instead of Cloud Run.
- **Cloud**: need `gcloud` authenticated → go to **2c**.

### 2c — Pre-flight (cloud path only)

Check and fix in order:

| Tool | Check | Fix |
|---|---|---|
| **gcloud** | `gcloud auth list` → active account | `gcloud auth login` |
| **GCP project** | `gcloud config get-value project` | `gcloud config set project shor-x-sinas` |

Fetch live Shor values — **never hardcode**:

```bash
SHOR_URL=$(gcloud run services describe shor-web \
  --region us-central1 --format "value(status.url)")

SHOR_TOKEN=$(gcloud secrets versions access latest \
  --secret=shor-engine-trigger-token --project=shor-x-sinas)
```

### 2d — Existing project check

Avoid duplicates:

```bash
curl -s "$SHOR_URL/external/projects" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  | jq -r '.projects[]? | "\(.id)  \(.name)  \(.targetUrl)"'
```

If a project already matches the target URL → ask the user: reuse or new?
Reuse → skip to **Phase 5**.

### 2e — Auth

Ask: "Does the target require authentication? (yes / no)"

Yes → build `authConfig` (see **Phase 4d**), then return here.
No → `authConfig = null`.

The accounts you supply are **in-scope test credentials** — a means of access the
scanner logs in with, never themselves a finding; the app's own auth and authz
stay the test surface (full framing in **4d**). To test broken access control /
IDOR, configure a **second identity** there.

**→ Go to Phase 5** (create project + scan).

---

## Phase 3 — White-box path

### 3a — Gather repositories

Ask:

> "List every repository in this project — backend, frontend, workers, config.
> One per line. Format: `owner/repo` (GitHub), local path, or ZIP."

Clone each one:

```bash
gh repo clone <owner/repo> /tmp/shor-analysis/<repo-name>
```

### 3b — Analyse the codebase

Run silently on each cloned repo. Report a concise summary to the user.

| What to check | Command | Action on result |
|---|---|---|
| Backend language | `find . -name 'Program.cs' -o -name 'main.go' -o -name 'app.py' -o -name 'index.js'` | Identify stack |
| Frontend / UI | `find . -name 'package.json' ! -path '*/node_modules/*'` | If missing → ask for UI repo |
| Auth pattern | `grep -rl 'Authorization\|Bearer\|ApiKey\|OIDC\|OAuth' --include='*.cs' --include='*.py' --include='*.ts'` | Note → used in 4d |
| Routes / endpoints | `grep -rl '\[Route\]\|@app.route\|router\.\(get\|post\)' ` | Note for attack surface |
| Database | `grep -rl 'MongoDB\|Postgres\|MySQL\|Redis'` | Note for injection config |
| Docker / Compose | `ls docker-compose*.yml Dockerfile* 2>/dev/null` | If present → reuse in 4c |
| Secrets in code | `grep -rEil '(password\|secret\|api.?key)\s*[:=]\s*["'"'"'][^"'"'"']{6,}'` | **Warn user immediately** |

If a frontend repo is missing:

> "I see a backend but no frontend/UI repo. Does the app have a web interface?
> Paste the repo — white-box coverage improves significantly."

### 3c — Compute recommendation (white-box specific)

After the analysis, count:
- Total lines of code: `find /tmp/shor-analysis -name '*.cs' -o -name '*.ts' -o -name '*.py' | xargs wc -l 2>/dev/null | tail -1`
- Number of service repos

Then give a specific recommendation:

| Codebase size | Recommendation |
|---|---|
| < 10k LOC, 1–2 repos | Local is fine — 8 GB RAM sufficient |
| 10k–50k LOC, 2–3 repos | Local works but cloud is faster |
| > 50k LOC or 3+ repos | **Cloud strongly recommended** — static analysis + 10 parallel agents will OOM a laptop |

Run the device check:

```bash
sysctl hw.memsize | awk '{printf "RAM: %.0f GB\n", $2/1073741824}'
sysctl hw.logicalcpu | awk '{print "CPU cores:", $2}'
docker info --format "Docker: {{.ServerVersion}}" 2>/dev/null || echo "Docker: not running"
```

Tell the user the numbers and your recommendation, then ask:

> "**Local or cloud?**"

### 3d — Pre-flight (based on choice)

Run only what's actually needed:

**Cloud** (recommended for white-box):

```bash
# Auth
gcloud auth list                            # must show active account
gcloud config get-value project             # should be shor-x-sinas

# GitHub CLI — needed to clone private repos + push pentest bundle
gh auth status

# Fetch Shor live values
SHOR_URL=$(gcloud run services describe shor-web \
  --region us-central1 --format "value(status.url)")
SHOR_TOKEN=$(gcloud secrets versions access latest \
  --secret=shor-engine-trigger-token --project=shor-x-sinas)
```

Fixes:
- `gcloud auth login` → re-auth
- `gcloud config set project shor-x-sinas` → set project
- `gh auth login` → GitHub auth

**Local** (white-box):

```bash
docker info   # Docker must be running
gh auth status  # still needed to clone private repos
```

### 3e — Existing project check

Same as 2d — check for duplicates before proceeding.

### 3f — Build the pentest repo

**Purpose**: one GitHub repo so Shor's static-analysis agents see the entire
codebase in one place.

```bash
gh repo create <github-username>/<appname>-pentest \
  --public --description "Shor pentest bundle — <app name>"

mkdir /tmp/pentest-bundle && cd /tmp/pentest-bundle && git init

# Copy each service into a named subdirectory
cp -r /tmp/shor-analysis/<backend-repo>  ./backend
cp -r /tmp/shor-analysis/<frontend-repo> ./frontend
# Add: ./workers, ./infra, ./shared — whatever was found
```

**Write `CODEBASE.md` automatically** based on what was found in 3b:

```markdown
# Pentest Codebase — <app name>

## Architecture
<one paragraph: what each subdirectory is and how they communicate>

## Auth mechanisms
<findings from the auth grep — endpoints, token types, middleware, OIDC config>

## Key attack surfaces
<routes list, file upload endpoints, external API calls, admin interfaces>

## Database layer
<type, ORM, connection pattern>

## Known credentials (pentest environment only — never prod secrets)
<API keys, test passwords, mock tokens set up for this pentest>
```

Push:

```bash
git add . && git commit -m "pentest bundle: <app name>"
git remote add origin https://github.com/<username>/<appname>-pentest.git
git push -u origin main
```

Record `PENTEST_REPO=<github-username>/<appname>-pentest`.

---

## Phase 4 — White-box: deploy the target

Ask: "Is the target already running at a public URL, or does it need to be deployed?"

**Already running** → record `TARGET_URL`, skip to **4d**.

**Needs deployment** → continue below.

### 4a — Create GCP VM

```bash
APP=<appname>   # e.g. "workflow"
ZONE=europe-west4-a

gcloud compute instances create ${APP}-pentest \
  --project=shor-x-sinas \
  --zone=$ZONE \
  --machine-type=e2-standard-4 \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=${APP}-pentest \
  --metadata=startup-script='#!/bin/bash
    apt-get update -y
    curl -fsSL https://get.docker.com | bash
    apt-get install -y docker-compose-plugin python3 python3-pip
    pip3 install flask pyjwt cryptography'

gcloud compute firewall-rules create ${APP}-pentest-allow \
  --project=shor-x-sinas \
  --allow=tcp:22,tcp:80,tcp:443,tcp:8080,tcp:8090 \
  --target-tags=${APP}-pentest

# Hardcode the IP — never fetch from metadata server (returns 404 in startup scripts)
EXTERNAL_IP=$(gcloud compute instances describe ${APP}-pentest \
  --zone=$ZONE --format="value(networkInterfaces[0].accessConfigs[0].natIP)")

TARGET_URL="http://$EXTERNAL_IP"
```

### 4b — Docker Compose stack

Read the repos from 3b to understand the runtime stack. Write a
`docker-compose.yml` adapted to what was found. Standard blocks:

```yaml
version: '3.8'
services:

  # ── OIDC / SSO auth server ───────────────────────────────────────────────────
  # Include ONLY when the app uses OIDC/SSO and can't reach its real IdP.
  mock-oidc:
    image: python:3.11-slim
    working_dir: /app
    volumes: [./mock-oidc:/app]
    ports: ["8090:8090"]
    command: python3 mock-oidc.py
    environment:
      ISSUER: "http://$EXTERNAL_IP:8090"
      CLIENT_ID: "<client-id-from-app-config>"

  # ── Database ──────────────────────────────────────────────────────────────────
  db:
    image: mongo:7          # swap for postgres:16 / mysql:8 as appropriate
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: admin
    volumes: [db-data:/data/db]

  # ── Backend API ───────────────────────────────────────────────────────────────
  api:
    build: ./backend
    ports: ["8080:8080"]
    environment:
      ASPNETCORE_ENVIRONMENT: Development
      DB_HOST: db                              # use service name, not localhost
      OIDC_ISSUER: "http://mock-oidc:8090"    # remove if no OIDC
      API_KEY: "pentest-key-shor2025"
      ALLOWED_ORIGINS: "http://$EXTERNAL_IP,http://$EXTERNAL_IP:80"
    depends_on: [db]

  # ── Frontend ──────────────────────────────────────────────────────────────────
  ui:
    build: ./frontend
    ports: ["80:80"]
    environment:
      VITE_API_URL: "http://$EXTERNAL_IP:8080"
    depends_on: [api]

volumes:
  db-data:
```

> **MongoDB TLS gotcha (.NET only)**: `MongoOptions.ConnectionString` appends
> `?tls=true` when the host name is not `localhost`. Using `db` as the service
> name triggers this and breaks TLS. Fix: wrap the API image with an entrypoint
> that patches `/etc/hosts` before starting the app:
>
> ```bash
> MONGO_IP=$(getent hosts db | awk '{print $1}')
> { echo "$MONGO_IP localhost"; grep -v '\blocalhost\b' /etc/hosts; } > /tmp/h
> cat /tmp/h > /etc/hosts    # in-place overwrite — never use sed -i (EBUSY on bind-mounts)
> exec dotnet YourApp.dll
> ```

### 4c — Mock OIDC server (if app uses SSO/OIDC)

Use when the app needs SurfConext, Keycloak, Auth0, or any OIDC IdP that
isn't accessible in the pentest environment.

```python
# mock-oidc/mock-oidc.py — auto-approving RS256 IdP
from flask import Flask, request, redirect, jsonify
import jwt, time, os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
ISSUER    = os.getenv("ISSUER", "http://localhost:8090")
CLIENT_ID = os.getenv("CLIENT_ID", "app-client")
_priv     = rsa.generate_private_key(65537, 2048, default_backend())

def _tok(sub, **extra):
    now = int(time.time())
    return jwt.encode({"iss": ISSUER, "sub": sub, "aud": CLIENT_ID,
        "exp": now+7200, "iat": now, "name": "Pentest User",
        "email": "pentest@target.local", **extra}, _priv, "RS256")

@app.get("/auth")              # auto-approve auth-code flow
def auth():
    r = request.args.get("redirect_uri","")
    s = request.args.get("state","")
    return redirect(f"{r}?code=pentest-code&state={s}")

@app.post("/token")            # issue RS256 access + id token
def token():
    return jsonify({"access_token": _tok("pentester"),
        "id_token": _tok("pentester", uids=["pentester"]),
        "token_type": "Bearer", "expires_in": 7200,
        "scope": "openid profile email"})

@app.post("/oidc/introspect")  # SurfConext-style introspection
def introspect():
    return jsonify({"active": True, "sub": "pentester",
        "name": "Pentest User", "email": "pentest@target.local",
        "uids": ["pentester"]})

# Stub any external API the app calls at startup to prevent crash-on-boot
@app.get("/external/roles")    # rename to match what the app actually calls
def roles(): return jsonify(["Admin"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)
```

### 4d — Auth setup

**These credentials are scaffolding, not a finding.** The accounts you configure
here are **in-scope test accounts** the scanner uses as a **means of access** —
session plumbing to reach authenticated surface. They are supplied through the
secrets/config seam (this `authConfig`), never pasted into prompts or logs, and
are **never themselves a finding**: a weak or hard-coded test password, or the
bare fact that the scanner holds a valid session, does not get reported. The
application's **own** authentication and authorization stay the test surface —
including the scanner **forging or tampering with the very tokens it was handed**
(stripping a JWT signature, swapping a user id, replaying a session) to probe the
app's own validation of them. This is **not** "auth is out of scope": only the
injected credentials are off-limits — real login, MFA, session, and authorization
flaws are exactly what the scan hunts for.

Determine auth type from the grep output in 3b:

| Pattern found in code | `login_type` | Credential to use |
|---|---|---|
| `ApiKey` / `X-API-Key` header | `api` | API key value as `password` |
| Form POST to `/login` | `form` | Username + password |
| OIDC / OAuth / SurfConext | `sso` | Mock OIDC token endpoint as `login_url` |
| `Authorization: Basic` | `basic` | Username + password |

Build the `authConfig` JSON (all four fields are required):

```json
{
  "authentication": {
    "login_type": "api",
    "login_url": "http://<EXTERNAL_IP>:8080",
    "credentials": {
      "username": "pentest",
      "password": "<API_KEY_OR_PASSWORD>"
    },
    "success_condition": {
      "type": "url_contains",
      "value": "<string that only appears in an authenticated response>"
    }
  }
}
```

**Verify auth before proceeding** — if this fails, debug now:

```bash
# API key
curl -sf "http://$EXTERNAL_IP:8080/api/me" \
  -H "Authorization: ApiKey $API_KEY" | jq .

# Bearer (from mock OIDC)
TOKEN=$(curl -sf -X POST "http://$EXTERNAL_IP:8090/token" | jq -r .access_token)
curl -sf "http://$EXTERNAL_IP:8080/api/me" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

#### Multi-identity ("second user") — broken access control / IDOR

To test **broken access control** — horizontal cross-account access (IDOR) and
vertical privilege escalation — configure **two or more identities**. Add an
`identities[]` array to `authentication` alongside the primary `credentials`
block. The primary `credentials` stays as the default/primary identity; each
entry in `identities[]` is a full login of its own, with the same
`credentials` shape (`username`, `password`, optional `totp_secret`) and an
optional per-identity `success_condition`. Give each a `label` and, optionally, a
`role`.

```json
{
  "authentication": {
    "login_type": "form",
    "login_url": "https://target.example/login",
    "credentials": {
      "username": "primary",
      "password": "<PRIMARY_PASSWORD>"
    },
    "success_condition": {
      "type": "url_contains",
      "value": "/dashboard"
    },
    "identities": [
      {
        "label": "attacker",
        "role": "member",
        "credentials": {
          "username": "low-priv",
          "password": "<ATTACKER_PASSWORD>"
        },
        "success_condition": {
          "type": "url_contains",
          "value": "/dashboard"
        }
      },
      {
        "label": "victim",
        "role": "member",
        "credentials": {
          "username": "victim",
          "password": "<VICTIM_PASSWORD>",
          "totp_secret": "<BASE32_SECRET>"
        },
        "success_condition": {
          "type": "url_contains",
          "value": "/dashboard"
        }
      }
    ]
  }
}
```

The model — same rail as the primary login, applied per identity:

- **Each identity is scaffolding.** Its credentials are a means of access, never a
  finding — exactly like the primary login above.
- **The access-control *differences* between identities are the findings.** The
  `attacker` identity reaching the `victim`'s objects or endpoints (a 200 where
  403/404/empty is expected) is broken object-level access control; a low-role
  identity performing or reaching a higher-role action is privilege escalation.
- **Prerequisite (check this FIRST) — the target must authenticate *distinct*
  users.** Before adding `identities[]`, confirm a *different* credential yields a
  *different* user with its own data. Many schemes collapse to ONE identity and
  cannot do cross-account testing no matter how many credentials you supply:
  - a single shared **API key** (every key-holder authenticates as the same
    service user — e.g. a handler that maps any valid key to one `ApiUserName`);
  - a single-user **dev/mock auth** (e.g. a `MockUserService` whose "current user"
    is hardcoded to one account, often with *all* roles);
  - a **service account** / machine token.
  Read the target's auth handler + user service to decide. If a different
  credential does NOT produce a different user, the target is single-identity —
  **do not fabricate a second identity** (it won't authenticate; the bootstrap
  just degrades to single-identity). Configure a single identity and accept the
  fallback below: the authz lane still runs **white-box static analysis** (it finds
  missing object-/role-level authorization checks by reading the code) plus
  single-user probing — only the *live two-account confirmation* is skipped. To get
  real cross-account testing on a single-auth target you control, you must first
  make the target expose ≥2 distinct users (e.g. make the mock user selectable per
  request and seed each with its own data) — that modifies the target, so do it
  deliberately, and ideally give the second user a *narrower* role so vertical
  escalation is meaningful too.
- **Prerequisite — seeded data.** The target must already hold **data owned by
  each identity** (orders, documents, messages, etc.) for cross-account probes to
  land; the `victim` needs real objects for the `attacker` to try to reach. With
  nothing seeded, the probes have nothing to hit.
- **Fewer than 2 identities → single-identity fallback.** The authorization lane
  then covers only the vertical and unauthenticated-vs-authenticated boundaries;
  horizontal cross-account testing is skipped for lack of a second identity.
- **ADR-050.** `label` and `role` are metadata used to plan and report the authz
  tests; the credentials flow through this config/secrets seam and never enter
  prompts or logs.

### 4e — Upload and start

```bash
gcloud compute scp --recurse /tmp/pentest-bundle ${APP}-pentest:/opt/target \
  --zone=$ZONE --project=shor-x-sinas

gcloud compute ssh ${APP}-pentest --zone=$ZONE --project=shor-x-sinas \
  --command="cd /opt/target && sudo docker compose up -d"

# Health check — wait 10 s then verify
sleep 10
gcloud compute ssh ${APP}-pentest --zone=$ZONE --project=shor-x-sinas \
  --command="sudo docker compose ps && curl -sf http://localhost:8080/ | head -c 200"
```

---

## Phase 5 — Create Shor project + start scan

### 5a — Create project

```bash
curl -s -X POST "$SHOR_URL/external/projects" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "<descriptive name>",
    "targetUrl": "'"$TARGET_URL"'",
    "mode": "whitebox",
    "repoRef": "'"$PENTEST_REPO"'",
    "authConfig": '"$AUTH_CONFIG_JSON"'
  }'
```

Omit `repoRef` for black-box. Omit `authConfig` (or set `null`) if no auth.
Record `PROJECT_ID` from the response.

### 5b — Start scan

```bash
curl -s -X POST "$SHOR_URL/external/scans" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"projectId\": \"$PROJECT_ID\"}"
```

Record `SCAN_ID`.

### 5c — Confirm it's running

```bash
curl -s "$SHOR_URL/external/scans/$SCAN_ID" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  | jq '{status, findingCount}'

gcloud run jobs executions list --job shor-scan-worker \
  --project shor-x-sinas --region us-central1 --limit 2 \
  --format="table(name,status.startTime,status.completionTime)"
```

`status: running` + an execution with no completion time = all good.

---

## Phase 6 — Hand-off

Tell the user:

---

**Setup complete.**

| | |
|---|---|
| **Shor dashboard** | `<SHOR_URL>` |
| **Project** | `<PROJECT_NAME>` · `<PROJECT_ID>` |
| **Scan** | `<SCAN_ID>` · status: running |
| **Target** | `<TARGET_URL>` |
| **Pentest repo** | `github.com/<PENTEST_REPO>` _(white-box only)_ |
| **Target VM** | `<VM_NAME>` / `<EXTERNAL_IP>` _(if deployed)_ |

**Pipeline**: pre-recon → recon → 5 vuln agents → 5 exploit agents → report.
White-box reads the full source in parallel. **Duration: 30–90 min.**

```bash
# Poll progress
curl -s "$SHOR_URL/external/scans/$SCAN_ID" \
  -H "Authorization: Bearer $SHOR_TOKEN" | jq '{status,findingCount}'

# Stop scan
curl -s -X DELETE "$SHOR_URL/external/scans/$SCAN_ID" \
  -H "Authorization: Bearer $SHOR_TOKEN"

# Tear down target VM (when done — stops billing)
gcloud compute instances delete <VM_NAME> --zone=<ZONE> --project=shor-x-sinas
gcloud compute firewall-rules delete <FIREWALL_RULE> --project=shor-x-sinas
```

---

## Reference — Shor external API

All calls: `Authorization: Bearer <shor-engine-trigger-token>`.

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/external/projects` | `{name, targetUrl, mode, repoRef?, authConfig?}` | `{projectId}` |
| `POST` | `/external/scans` | `{projectId, provider?}` | `{scanId, status}` |
| `GET` | `/external/scans/:id` | — | `{scanId, status, progress, findingCount, startedAt, finishedAt}` |

**`authConfig` — full schema** (all four top-level fields required when set):

```json
{
  "authentication": {
    "login_type": "form | sso | api | basic",
    "login_url": "<valid URI>",
    "credentials": {
      "username": "<str>",
      "password": "<str>",
      "totp_secret": "<base32 — only if MFA is required>"
    },
    "success_condition": {
      "type": "url_contains | text_contains | element_present | url_equals_exactly",
      "value": "<str>"
    },
    "login_flow": ["optional: step-by-step natural language instructions"],
    "identities": [
      {
        "label": "<str>",
        "role": "<optional str>",
        "credentials": { "username": "<str>", "password": "<str>", "totp_secret": "<optional base32>" },
        "success_condition": { "type": "<same enum as above>", "value": "<str>" }
      }
    ]
  }
}
```

`login_flow` and `identities` are optional. Supply `identities[]` to test broken
access control / IDOR — see the multi-identity setup in **4d**; each entry is a
full login with the same `credentials` shape as the primary identity.

## Reference — Common failures

| Symptom | Cause | Fix |
|---|---|---|
| API container exits immediately | Missing required env var | `docker compose logs api` → read the error, add the missing var |
| `MongoDB TLS` / auth failed | `.NET` host ≠ `localhost` adds `?tls=true` | `/etc/hosts` patch entrypoint (see 4b) |
| `sed -i` fails on `/etc/hosts` | Bind-mount EBUSY — can't rename | Use `cat /tmp/new > /etc/hosts` instead |
| 401 after login | CORS / cookie domain mismatch | Set `ALLOWED_ORIGINS` + `FRONTEND_BASE_URL` |
| Scan stays `pending` | Worker job not launched | Check `gcloud run jobs executions list` |
| Scan fails immediately | Invalid `authConfig` | All 4 fields required; validate schema |
| VM startup script fails silently | Metadata server 404 | Hardcode `EXTERNAL_IP` — don't use metadata endpoint in startup scripts |
| nohup process dies on SSH close | SSH session ends → child dies | Use `sudo systemd-run --unit=<name> /bin/bash /script.sh` instead |
