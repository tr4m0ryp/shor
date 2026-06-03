# syntax=docker/dockerfile:1
#
# Aegis worker APP image — the thin, fast-changing half.
#
# `FROM` the prebuilt toolkit base (`aegis-worker-base`, built by
# infra/docker/Dockerfile.base) and layer ONLY the compiled Node worker + skills
# on top. The ~30 offensive tools, the Python venv, chromium and the Claude CLI
# all live in the base, so this build skips all ~50 tool-install steps and
# finishes in ~1-2 min instead of ~14.
#
# Build: .acceptance/cloudbuild.yaml (passes BASE_IMAGE). Rebuild the base only
# when tools.lock / system deps change; rebuild THIS on every worker code change.

# Global ARG (declared before the first FROM so it is usable in the runtime
# stage's FROM). Cloud Build overrides it; the default keeps local builds working.
ARG BASE_IMAGE=us-central1-docker.pkg.dev/aegis-avelero-test/aegis/aegis-worker-base:latest

# ---------------------------------------------------------------------------
# Stage A: node-builder — build the Aegis worker (Node) + prune to prod deps.
# ---------------------------------------------------------------------------
# hadolint ignore=DL3018
FROM cgr.dev/chainguard/wolfi-base:latest AS node-builder

RUN apk update && apk add --no-cache nodejs-22 npm git bash
RUN npm install -g pnpm@10.33.0

WORKDIR /app
# Manifests first for install-layer caching.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json ./
COPY infra/config ./infra/config
COPY apps/worker/package.json ./apps/worker/
COPY apps/web/package.json ./apps/web/
RUN pnpm install --frozen-lockfile

# Worker source + build.
COPY apps/worker ./apps/worker
RUN pnpm --filter @aegis/worker run build

# Prune to production dependencies (drops devDeps; keeps the pnpm workspace layout).
RUN rm -rf node_modules apps/worker/node_modules apps/web/node_modules && \
    pnpm install --frozen-lockfile --prod

# ---------------------------------------------------------------------------
# Stage B: runtime — the toolkit base + the Node app on top.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS runtime

# The base ends as the nonroot user; switch to root to lay down the app, then
# back. ENV/PATH/ENTRYPOINT are inherited from the base.
USER root

# 5) Aegis worker app (Node): dist + prod node_modules + prompts, from node-builder.
#    Kept in the pnpm workspace layout at /opt/aegis/app so the symlinked
#    node_modules resolve. WORKER_ROOT (paths.ts) → apps/worker; PROMPTS_DIR →
#    apps/worker/prompts (both present here).
COPY --from=node-builder /app/node_modules /opt/aegis/app/node_modules
COPY --from=node-builder /app/apps/worker /opt/aegis/app/apps/worker
COPY --from=node-builder /app/package.json /app/pnpm-workspace.yaml /opt/aegis/app/

# 6) Per-tool skills the Claude Agent SDK loads on demand (progressive disclosure).
#    HOME=/tmp + settingSources:["user"] → the SDK discovers ~/.claude/skills.
#    The repo groups skills into nested category dirs (recon/{discovery,scanning,
#    crawling}/, exploit/{injection,xss,auth,ssrf,authz,browser}/, static-analysis/
#    {secrets,code,dependencies}/) for organisation; flatten them here (find at any
#    depth) so each skill sits directly under the discovery root, which the SDK
#    scans one level deep: skills/<name>/SKILL.md.
COPY skills/ /tmp/aegis-skills-src/
RUN mkdir -p /tmp/.claude/skills && \
    find /tmp/aegis-skills-src -name SKILL.md -type f -exec sh -c \
      'cp -r "$(dirname "$1")" /tmp/.claude/skills/' _ {} \; && \
    rm -rf /tmp/aegis-skills-src

# 7) save-deliverable / generate-totp CLIs that the prompts invoke by name.
RUN ln -sf /opt/aegis/app/apps/worker/dist/scripts/save-deliverable.js /usr/local/bin/save-deliverable && \
    ln -sf /opt/aegis/app/apps/worker/dist/scripts/generate-totp.js /usr/local/bin/generate-totp && \
    chmod +x /opt/aegis/app/apps/worker/dist/scripts/*.js 2>/dev/null || true

# Own the laid-down app + skills as the nonroot runtime user.
RUN chown -R 65532:65532 /opt/aegis/app /tmp/.claude

USER 65532
WORKDIR /work

# Default: run one scan (the per-scan Job command, ADR-051). job-entry.js reads
# the scan params from the environment (AEGIS_*) and runs the pipeline, then exits.
CMD ["node", "/opt/aegis/app/apps/worker/dist/job-entry.js"]
