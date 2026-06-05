---
name: shor-setup
description: >
  Full interactive setup guide for Shor (the web-security scanning platform).
  Invoke when a user wants to pentest a target: guides pre-flight, scan-type
  selection, pentest repo creation, GCP or local deployment, auth wiring, and
  Shor project + scan creation. Handles black-box and white-box modes.
metadata:
  type: setup-guide
  version: "1.0.0"
---

# Shor Setup — Interactive Pentest Wizard

**What this skill does**: walks from zero to a running Shor scan in one session.
Covers pre-flight, target analysis, repo bundling, deployment, auth, and the
final `POST /external/scans`. Read each phase top-to-bottom and ask the user
ONLY the questions listed — no extras.

---

## Phase 0 — Pre-flight

**Tell the user** (one message, no confirmation needed):

> "I'm going to set up a Shor pentest project. Before we start I need to verify
> your environment. Answer the prompts below."

Check in order. If anything is missing, give the exact fix command.

### 0.1 Required CLI tools

| Tool | Check | Fix if missing |
|---|---|---|
| **gcloud** | `gcloud auth list` → active account | `gcloud auth login` |
| **GCP project** | `gcloud config get-value project` → `shor-x-sinas` | `gcloud config set project shor-x-sinas` |
| **gh** (GitHub CLI) | `gh auth status` | `gh auth login` |
| **docker** | `docker info` (skip if cloud-only) | install Docker Desktop |

### 0.2 Shor deployment URL + token

Fetch live values — never hardcode:

```bash
# Shor web URL
gcloud run services describe shor-web \
  --region us-central1 --format "value(status.url)"

# Engine trigger token (for all /external/* API calls)
gcloud secrets versions access latest \
  --secret=shor-engine-trigger-token --project=shor-x-sinas
```

Store both as `SHOR_URL` and `SHOR_TOKEN` for later phases.

### 0.3 Existing project check

**Avoid duplicates.** List current projects:

```bash
curl -s "$SHOR_URL/external/projects" \
  -H "Authorization: Bearer $SHOR_TOKEN" | jq '.projects[] | {id, name, targetUrl}'
```

If a project already exists for the same target, **ask the user** whether to
reuse it or create a new one. If reuse → skip to Phase 4.

---

## Phase 1 — Scan type + deployment location

Ask **two questions** in one message:

> **1. Scan type**
> - **Black-box** — you only have a URL. Shor tests the live app from the outside.
> - **White-box** — you have the source code. Shor reads the code + tests live.
>   White-box finds more; requires a GitHub repo.
>
> **2. Deployment**
> - **Cloud (GCP)** — target + Shor worker run on Google Cloud. Recommended.
> - **Local** — everything runs on this machine. Faster iteration, no cloud cost,
>   but limited by device specs.

Capture both answers before proceeding.

### Local viability check (if user picks Local)

Run and show the user:

```bash
sysctl hw.memsize | awk '{printf "RAM: %.0f GB\n", $2/1073741824}'
sysctl hw.logicalcpu | awk '{print "CPU cores:", $2}'
docker info --format "Docker: {{.ServerVersion}}"
```

**Recommend Cloud if**: RAM < 16 GB, cores < 8, or Docker is not running.
Explain: Shor runs up to 10 parallel agent + browser sessions; on a weak
machine scans timeout or OOM-kill.

If user insists on local: note they need a Claude API key and will run Shor
entirely in Docker Compose locally (no Cloud Run, no GCP billing). Skip all
`gcloud run` steps and use local `docker compose up` equivalents throughout.

---

## Phase 2 — Black-box path

**Ask**: target URL (must include scheme, e.g. `https://app.example.com`).

Validate:

```bash
curl -sf "$TARGET_URL" -o /dev/null && echo OK || echo "URL unreachable — fix before proceeding"
```

**Auth?** Ask: "Does the target require authentication to test authenticated
routes?" If yes → jump to **Phase 3d** (Auth setup), then return here.

Create project and start scan (Phase 4). Done.

---

## Phase 3 — White-box path

### 3a — Gather repositories

Ask:

> "List every repository involved in this project.
> Include backend, frontend, workers, and config repos.
> Format: `owner/repo` (GitHub), local path, or ZIP — one per line."

For each repo, **clone and analyse** it:

```bash
gh repo clone <owner/repo> /tmp/shor-analysis/<repo>
```

**Check for common patterns** and tell the user what you found:

| Check | Command | Flag if… |
|---|---|---|
| Backend language | `find . -name 'Program.cs' -o -name 'main.go' -o -name 'app.py'` | none found → ask |
| Frontend / UI | `find . -name 'package.json' -not -path '*/node_modules/*'` | missing → ask if there's a UI repo |
| Auth mechanism | `grep -r 'Authorization\|Bearer\|ApiKey\|OIDC\|OAuth' --include='*.cs' --include='*.py' --include='*.ts' -l` | output → used in Phase 3d |
| API routes | `grep -r '\[Route\|@app.route\|router\.\(get\|post\|put\|delete\)' -l` | list for attack surface note |
| Database type | `grep -r 'MongoDB\|Postgres\|MySQL\|Redis' -rl` | note for injection config |
| Docker / compose | `ls docker-compose*.yml Dockerfile* 2>/dev/null` | present → can deploy directly |
| Secrets in repo | `grep -rE '(password|secret|api.?key)\s*[:=]\s*["\x27][^"\x27]{6,}' -i -l` | **warn user immediately** |

**Ask about missing pieces.** E.g. if there's a `.NET` backend but no UI repo:
> "I see a backend but no frontend repo. Does the app have a web UI?
> If so, paste its repo — it improves coverage."

### 3b — Create pentest repo

**Purpose**: one GitHub repo with full codebase context so Shor's static-analysis
agents see the whole picture at once.

```bash
# Create public repo under user's account
gh repo create <username>/workflow-pentest --public --description "Shor pentest bundle"

mkdir /tmp/pentest-bundle
cd /tmp/pentest-bundle && git init
```

Copy each repo into a named subdirectory:

```bash
cp -r /tmp/shor-analysis/workflow-api  ./backend
cp -r /tmp/shor-analysis/workflow-ui   ./frontend
# add more as needed: ./workers, ./infra, etc.
```

**Write `CODEBASE.md`** — Claude writes this automatically based on what was
found in 3a. Include:

```markdown
# Pentest Codebase — <project name>

## Architecture
<brief: what each subdirectory is, how they talk>

## Auth mechanisms
<everything found in the auth grep — login endpoints, token types, middleware>

## Key attack surfaces
<routes, endpoints, file uploads, external APIs>

## Database layer
<type, connection pattern, ORM>

## Known credentials (pentest environment only)
<API keys, test passwords, mock tokens — NEVER prod secrets>
```

Push:

```bash
git add . && git commit -m "pentest bundle"
gh repo push
```

Record `PENTEST_REPO=<username>/workflow-pentest`.

### 3c — Deploy the target

Ask: "Is the target already deployed at a public URL, or do I need to deploy it?"

**If already deployed**: record URL → skip to 3d.

**If needs deployment** (most common for forked repos):

#### 3c-i Create GCP VM

```bash
gcloud compute instances create <app-name>-pentest \
  --project=shor-x-sinas \
  --zone=europe-west4-a \
  --machine-type=e2-standard-4 \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=pentest-target \
  --metadata=startup-script='#! /bin/bash
    apt-get update -y
    curl -fsSL https://get.docker.com | bash
    apt-get install -y docker-compose-plugin python3 python3-pip'
```

Open necessary ports:

```bash
gcloud compute firewall-rules create <app-name>-pentest-allow \
  --project=shor-x-sinas \
  --allow=tcp:22,tcp:80,tcp:443,tcp:8080,tcp:8090 \
  --target-tags=pentest-target
```

Get external IP:

```bash
EXTERNAL_IP=$(gcloud compute instances describe <app-name>-pentest \
  --zone=europe-west4-a --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
```

#### 3c-ii Docker Compose stack

**Inspect the repos** (from 3a) to understand the runtime stack, then write a
`docker-compose.yml` that wires the services together.

**Standard service blocks** (adapt to what was found):

```yaml
version: '3.8'
services:

  # ── Auth server ─────────────────────────────────────────────────────────────
  # Include ONLY if the app uses OIDC/SSO and needs an IdP to function.
  # Replace with real IdP URL if one is available in the pentest scope.
  mock-oidc:
    image: python:3.11-slim
    working_dir: /app
    volumes: [./mock-oidc:/app]
    ports: ["8090:8090"]
    command: python3 mock-oidc.py
    environment:
      ISSUER: "http://$EXTERNAL_IP:8090"
      CLIENT_ID: "<oidc-client-id-from-app-config>"

  # ── Database ─────────────────────────────────────────────────────────────────
  db:
    image: mongo:7        # or postgres:16, mysql:8 — match what the app uses
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: admin
    volumes: [db-data:/data/db]

  # ── Backend API ───────────────────────────────────────────────────────────────
  api:
    build: ./backend
    ports: ["8080:8080"]
    environment:
      # Database connection — point at service name, NOT "localhost"
      # Exception: .NET MongoOptions adds ?tls=true when host != localhost.
      # If that applies, use the /etc/hosts patch (see "MongoDB TLS gotcha" below).
      DB_HOST: db
      ASPNETCORE_ENVIRONMENT: Development   # or NODE_ENV=development etc.
      # Auth / OIDC
      OIDC_ISSUER: "http://mock-oidc:8090"
      # API key for authenticated pentest access
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

> **MongoDB TLS gotcha**: if the .NET app's `ConnectionString` appends `?tls=true`
> when the host is NOT `localhost`, the container will fail TLS validation for
> service names like `mongodb`. Fix: wrap the API image with an entrypoint that
> patches `/etc/hosts` so the DB service name resolves to `localhost`:
>
> ```bash
> MONGO_IP=$(getent hosts db | awk '{print $1}')
> { echo "$MONGO_IP localhost"; grep -v '\blocalhost\b' /etc/hosts; } > /tmp/h
> cat /tmp/h > /etc/hosts   # in-place overwrite — never use sed -i (EBUSY)
> exec dotnet YourApp.dll
> ```

#### 3c-iii Mock OIDC server (if needed)

When the app uses SurfConext, Keycloak, Auth0, or any OIDC provider that
isn't reachable in the pentest env, generate a self-contained Flask IdP:

```python
# mock-oidc/mock-oidc.py
from flask import Flask, request, redirect, jsonify
import jwt, json, time, os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
ISSUER     = os.environ.get("ISSUER", "http://localhost:8090")
CLIENT_ID  = os.environ.get("CLIENT_ID", "app-client")
private_key = rsa.generate_private_key(65537, 2048, default_backend())
pub_key     = private_key.public_key()

def make_token(sub, extra={}):
    now = int(time.time())
    return jwt.encode({
        "iss": ISSUER, "sub": sub, "aud": CLIENT_ID,
        "exp": now + 7200, "iat": now, "name": "Pentest User",
        "email": "pentest@target.local",
        **extra
    }, private_key, algorithm="RS256")

@app.get("/auth")           # Auto-approve auth code flow
def auth():
    redirect_uri = request.args.get("redirect_uri","")
    state = request.args.get("state","")
    code = "pentest-code"
    return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.post("/token")         # Issue RS256 JWT
def token():
    return jsonify({
        "access_token": make_token("pentester"),
        "id_token":     make_token("pentester", {"uids":["pentester"]}),
        "token_type": "Bearer", "expires_in": 7200,
        "scope": "openid profile email",
    })

@app.post("/oidc/introspect")   # SurfConext-style introspection
def introspect():
    return jsonify({"active":True,"sub":"pentester","name":"Pentest User",
                    "email":"pentest@target.local","uids":["pentester"]})

# Add stubs for any external API the app calls at startup (prevents crash)
@app.get("/datanose/api/Common/Roles/GetRolesForUser")
def roles(): return jsonify(["Coordinator","Admin"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)
```

Install deps on VM: `pip3 install flask pyjwt cryptography`.

#### 3c-iv Upload + start

```bash
# Upload compose stack to VM
gcloud compute scp --recurse /tmp/pentest-bundle <vm-name>:/opt/target \
  --zone=europe-west4-a --project=shor-x-sinas

# SSH in and start
gcloud compute ssh <vm-name> --zone=europe-west4-a --project=shor-x-sinas \
  --command="cd /opt/target && sudo docker compose up -d"

# Verify stack is healthy
sleep 10
gcloud compute ssh <vm-name> --zone=europe-west4-a --project=shor-x-sinas \
  --command="sudo docker compose ps && curl -sf http://localhost:8080/health || curl -sf http://localhost:8080/"
```

Record `TARGET_URL=http://$EXTERNAL_IP`.

### 3d — Auth setup

**Determine auth type** from the grep output in 3a:

| Auth pattern found | `login_type` | Notes |
|---|---|---|
| `ApiKey` / `X-API-Key` header | `api` | Set key in `credentials.password` |
| Username + password form | `form` | Set `login_url` to the login page |
| OAuth 2.0 / OIDC / SSO | `sso` | Use mock OIDC token endpoint as `login_url` |
| HTTP Basic | `basic` | Standard username/password |

Build the `authConfig` object (must match this schema exactly):

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
      "value": "<string present in response on successful auth>"
    }
  }
}
```

**Verify auth works** before creating the project:

```bash
# API key example
curl -sf "http://$EXTERNAL_IP:8080/api/me" \
  -H "Authorization: ApiKey $API_KEY" | jq .

# Bearer token example (from mock OIDC)
TOKEN=$(curl -sf -X POST "http://$EXTERNAL_IP:8090/token" \
  -d "grant_type=password" | jq -r .access_token)
curl -sf "http://$EXTERNAL_IP:8080/api/me" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

If the auth call returns user data → proceed. If not → debug before moving on.

---

## Phase 4 — Create Shor project + start scan

### 4a — Create project

```bash
curl -s -X POST "$SHOR_URL/external/projects" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "<descriptive project name>",
    "targetUrl": "<TARGET_URL>",
    "mode": "whitebox",              # or "blackbox"
    "repoRef": "<PENTEST_REPO>",     # omit for black-box
    "authConfig": <AUTH_CONFIG_JSON> # omit if no auth
  }'
```

Record `PROJECT_ID` from the response.

### 4b — Start scan

```bash
curl -s -X POST "$SHOR_URL/external/scans" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"projectId\": \"$PROJECT_ID\"}"
```

Record `SCAN_ID`.

### 4c — Confirm it's running

```bash
curl -s "$SHOR_URL/external/scans/$SCAN_ID" \
  -H "Authorization: Bearer $SHOR_TOKEN" | jq '{status, progress, findingCount}'
```

Status should be `running`. Also verify a Cloud Run execution started:

```bash
gcloud run jobs executions list --job shor-scan-worker \
  --project shor-x-sinas --region us-central1 --limit 2
```

Newest execution with no `COMPLETION_TIME` = running correctly.

---

## Phase 5 — Hand-off to user

Tell the user (replace values):

---

**Setup complete.** Here's your pentest:

| | |
|---|---|
| **Shor dashboard** | `<SHOR_URL>` |
| **Project** | `<PROJECT_NAME>` (`<PROJECT_ID>`) |
| **Target** | `<TARGET_URL>` |
| **Scan ID** | `<SCAN_ID>` |
| **Pentest repo** | `github.com/<PENTEST_REPO>` |
| **Target VM** | `<VM_NAME>` / `<EXTERNAL_IP>` (if deployed) |

**What's running**: Shor's pipeline (pre-recon → recon → 5 vuln agents →
5 exploit agents → synthesis report). White-box mode reads the full codebase
in parallel. Estimated duration: 30–90 min depending on app size.

**To check progress**: open the dashboard or poll:
```bash
curl -s "$SHOR_URL/external/scans/$SCAN_ID" \
  -H "Authorization: Bearer $SHOR_TOKEN" | jq '{status,findingCount}'
```

**To stop the scan**:
```bash
curl -s -X DELETE "$SHOR_URL/external/scans/$SCAN_ID" \
  -H "Authorization: Bearer $SHOR_TOKEN"
```

**To tear down the target VM when done**:
```bash
gcloud compute instances delete <VM_NAME> --zone=<ZONE> --project=shor-x-sinas
gcloud compute firewall-rules delete <FIREWALL_RULE> --project=shor-x-sinas
```

---

## Reference — Shor external API

All calls require `Authorization: Bearer <shor-engine-trigger-token>`.

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/external/projects` | `{name, targetUrl, mode, repoRef?, authConfig?}` | `{projectId}` |
| `POST` | `/external/scans` | `{projectId, provider?}` | `{scanId, status}` |
| `GET` | `/external/scans/:id` | — | `{scanId, status, progress, findingCount, startedAt, finishedAt}` |

**`authConfig` schema** (full, all fields required when present):

```json
{
  "authentication": {
    "login_type": "form | sso | api | basic",
    "login_url": "<uri>",
    "credentials": { "username": "<str>", "password": "<str>" },
    "success_condition": { "type": "url_contains | text_contains | element_present | url_equals_exactly", "value": "<str>" },
    "login_flow": ["optional step-by-step instructions for the agent"],
    "totp_secret": "<base32 if MFA is required>"
  }
}
```

## Reference — Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| API container exits immediately | Missing required env var (API key, OIDC URL) | `docker compose logs api` → read the error |
| `MongoDB TLS` / `auth failed` | `.NET` host != `localhost` adds `?tls=true` | Use `/etc/hosts` patch entrypoint (see 3c-ii) |
| `sed -i` fails on `/etc/hosts` | Bind-mount EBUSY | Use `cat /tmp/new > /etc/hosts` not `sed -i` |
| Auth returns 401 after login | Cookie domain mismatch or CORS | Set `ALLOWED_ORIGINS` and `FRONTEND_BASE_URL` |
| Scan status stays `pending` | Worker job not triggered | Check `gcloud run jobs executions list` |
| Scan fails immediately | Config YAML invalid | Validate authConfig schema — all 4 fields required |
| VM startup script incomplete | Cloud Build metadata 404 | Hardcode `EXTERNAL_IP` — don't rely on metadata server |
