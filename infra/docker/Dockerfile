# syntax=docker/dockerfile:1
#
# Aegis offensive-toolkit image (multi-stage, Wolfi/glibc).
#
# Ported from storron's infra/docker/Dockerfile MINUS all Tor/onion machinery
# (onionscan-builder, torsocks-builder, every torsocks/onion COPY). Aegis runs
# direct clearnet egress only (LAUNCH-SPEC §1, ADR-004/022/041).
#
# Strategy (LAUNCH-SPEC §5.2, ADR-023/024/026/027):
#   - Builder  : cgr.dev/chainguard/wolfi-base  (apk + shell; build everything)
#   - Runtime  : cgr.dev/chainguard/glibc-dynamic  (minimal; binaries + venv copied in)
#   - Wolfi is glibc (not musl), so PyPI wheels + CGO binaries install natively.
#   - NEVER copy Alpine/musl binaries: ABI-incompatible (ld-musl vs libc.so.6).
#     Everything below is built from source / installed from glibc wheels.
#   - One shared Python venv at /opt/aegis/venv on PATH (no --break-system-packages).
#   - git-clone tools pinned to a SHA in tools.lock for reproducibility.
#
# Tool matrix: LAUNCH-SPEC §5.3 (ADR-025). Per-host glibc gotchas:
#   - naabu needs libpcap-dev at build time / libpcap at runtime.
#   - katana is built CGO_ENABLED=1 (gcc + Go 1.25+) for the headless path.
#   - Playwright chromium needs glibc nss/freetype/harfbuzz/X11 libs via apk.

# ---------------------------------------------------------------------------
# Stage 1: go-builder — compile all Go tools against Wolfi glibc.
# ---------------------------------------------------------------------------
# katana needs Go 1.25+ for its headless build; Wolfi's default `go` package
# can lag, so pin the toolchain explicitly via the go-1.25 apk package.
FROM cgr.dev/chainguard/wolfi-base:latest AS go-builder

# hadolint ignore=DL3018
RUN apk update && apk add --no-cache \
    build-base \
    git \
    ca-certificates \
    go-1.25 \
    # naabu/pcap-backed scanners link against libpcap at build time
    libpcap-dev \
    linux-headers

ENV GOPATH=/go
ENV PATH=/usr/lib/go-1.25/bin:/go/bin:$PATH
# CGO is required for katana's headless build (and harmless for the rest, but
# we flip it per-install below to keep pure-Go tools statically linked).
ENV GOFLAGS=-buildvcs=false

RUN mkdir -p /go/bin

# Retry wrapper: the Go module proxy occasionally drops an HTTP/2 stream
# mid-download (transient, not a code issue). Retry so a long build is not
# wasted on a flaky fetch.
RUN printf '#!/bin/sh\nn=0\nuntil "$@"; do n=$((n+1)); [ "$n" -ge 5 ] && echo "retry: gave up after $n: $*" >&2 && exit 1; echo "retry $n/5: $*" >&2; sleep 8; done\n' > /usr/local/bin/retry && chmod +x /usr/local/bin/retry

# --- ProjectDiscovery + pure-Go tools (CGO off → portable static binaries) ---
# Versions float to @latest per ADR-025; the runtime is reproducible from this Dockerfile.
ENV CGO_ENABLED=0
RUN retry go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    retry go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    retry go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    retry go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    retry go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
RUN retry go install -v github.com/ffuf/ffuf/v2@latest && \
    retry go install -v github.com/hahwul/dalfox/v2@latest && \
    retry go install -v github.com/Emoe/kxss@latest && \
    retry go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    retry go install -v github.com/tomnomnom/waybackurls@latest
# trufflehog dropped: its go.mod uses `replace` directives, which `go install
# <mod>@latest` rejects. gitleaks already covers secret scanning, so it is redundant.
RUN retry go install -v github.com/zricethezav/gitleaks/v8@latest && \
    retry go install -v github.com/google/osv-scanner/v2/cmd/osv-scanner@latest

# --- naabu needs CGO + libpcap ---
ENV CGO_ENABLED=1
RUN retry go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# --- katana: CGO_ENABLED=1 for the headless (chromedp) build path (ADR-025) ---
RUN retry go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# --- nosqli: no documented @latest; pinned to a commit SHA from tools.lock ---
ARG NOSQLI_SHA
RUN retry env CGO_ENABLED=0 go install -v "github.com/Charlie-belmer/nosqli@${NOSQLI_SHA}"

# ---------------------------------------------------------------------------
# Stage 2: py-builder — build the shared Python venv against Wolfi glibc.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS py-builder

# build-base + headers cover any sdist that lacks a glibc wheel.
# hadolint ignore=DL3018
RUN apk update && apk add --no-cache \
    build-base \
    git \
    curl \
    ca-certificates \
    python-3.13 \
    python-3.13-dev \
    py3.13-pip \
    libffi-dev \
    openssl-dev

# Shared venv on PATH — ADR-026. No --break-system-packages; keeps apk Python clean.
ENV VENV=/opt/aegis/venv
RUN python3 -m venv "$VENV"
ENV PATH=$VENV/bin:$PATH

# Pinned git-clone Python tools live here; their requirements install into the venv.
ENV TOOLS_DIR=/opt/aegis/tools
RUN mkdir -p "$TOOLS_DIR"

# Upgrade installer tooling first so wheels resolve cleanly on glibc.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# --- PyPI tools (official glibc wheels) ---
# NOTE: paramspider is NOT on PyPI (verified: `pip install paramspider` fails);
# it installs from its git checkout below.
RUN pip install --no-cache-dir \
    semgrep \
    arjun \
    wafw00f \
    playwright

# --- git-clone Python tools, pinned to SHAs from tools.lock (ADR-027) ---
# Cloned with --depth 1 then checked out to the exact pinned commit. Each tool
# runs in place (python <tool>.py); its requirements install into the shared venv.
ARG SQLMAP_SHA
ARG COMMIX_SHA
ARG SSTIMAP_SHA
ARG XSSTRIKE_SHA
ARG SSRFMAP_SHA
ARG JWT_TOOL_SHA
ARG PARAMSPIDER_SHA

# Generic pinned-clone helper kept inline (no shell helper in runtime stage).
# sqlmap: pure-Python, runs in place; pip packaging lags upstream.
RUN git clone --filter=blob:none https://github.com/sqlmapproject/sqlmap.git "$TOOLS_DIR/sqlmap" && \
    git -C "$TOOLS_DIR/sqlmap" checkout --detach "$SQLMAP_SHA"
# commix: pure-Python stdlib, runs in place (no requirements.txt).
RUN git clone --filter=blob:none https://github.com/commixproject/commix.git "$TOOLS_DIR/commix" && \
    git -C "$TOOLS_DIR/commix" checkout --detach "$COMMIX_SHA"
# SSTImap: py3, requirements into venv.
RUN git clone --filter=blob:none https://github.com/vladko312/SSTImap.git "$TOOLS_DIR/SSTImap" && \
    git -C "$TOOLS_DIR/SSTImap" checkout --detach "$SSTIMAP_SHA" && \
    pip install --no-cache-dir -r "$TOOLS_DIR/SSTImap/requirements.txt"
# XSStrike: py3, requirements into venv.
RUN git clone --filter=blob:none https://github.com/s0md3v/XSStrike.git "$TOOLS_DIR/XSStrike" && \
    git -C "$TOOLS_DIR/XSStrike" checkout --detach "$XSSTRIKE_SHA" && \
    pip install --no-cache-dir -r "$TOOLS_DIR/XSStrike/requirements.txt"
# SSRFmap: pure-Python, runs in place, requirements into venv.
RUN git clone --filter=blob:none https://github.com/swisskyrepo/SSRFmap.git "$TOOLS_DIR/SSRFmap" && \
    git -C "$TOOLS_DIR/SSRFmap" checkout --detach "$SSRFMAP_SHA" && \
    pip install --no-cache-dir -r "$TOOLS_DIR/SSRFmap/requirements.txt"
# jwt_tool: pure-Python (pycryptodomex), requirements into venv, pinned (13mo stale).
RUN git clone --filter=blob:none https://github.com/ticarpi/jwt_tool.git "$TOOLS_DIR/jwt_tool" && \
    git -C "$TOOLS_DIR/jwt_tool" checkout --detach "$JWT_TOOL_SHA" && \
    pip install --no-cache-dir -r "$TOOLS_DIR/jwt_tool/requirements.txt"
# paramspider: NOT on PyPI; install from the pinned checkout (setup.py provides a
# `paramspider` console script, so it lands on the venv PATH directly).
RUN git clone --filter=blob:none https://github.com/devanshbatham/ParamSpider.git "$TOOLS_DIR/ParamSpider" && \
    git -C "$TOOLS_DIR/ParamSpider" checkout --detach "$PARAMSPIDER_SHA" && \
    pip install --no-cache-dir "$TOOLS_DIR/ParamSpider"

# Strip the .git history from each clone to slim the layer and freeze the pin.
RUN find "$TOOLS_DIR" -maxdepth 2 -name .git -type d -prune -exec rm -rf {} +

# ---------------------------------------------------------------------------
# Stage 2b: node-builder — build the Aegis worker (Node) + prune to prod deps.
# ---------------------------------------------------------------------------
# The worker is the per-scan agent pipeline (Claude Agent SDK). Built here against
# the repo (build context = repo root), then its dist + prod node_modules + prompts
# are copied into the runtime. hadolint ignore=DL3018
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
# Stage 3: runtime-staging — collect glibc runtime libraries + nmap + chromium.
# ---------------------------------------------------------------------------
# glibc-dynamic has no apk/shell, so we apk-install the runtime closure here
# (against the SAME Wolfi glibc as the builders) and copy it forward. Every lib
# is glibc-ABI, never musl.
FROM cgr.dev/chainguard/wolfi-base:latest AS runtime-staging

# hadolint ignore=DL3018
RUN apk update && apk add --no-cache \
    # core runtime utilities the agent + tools shell out to
    bash \
    git \
    curl \
    ca-certificates \
    coreutils \
    grep \
    sed \
    findutils \
    # packaged scanner
    nmap \
    nmap-scripts \
    # interpreter for the venv (matches py-builder's python-3.13)
    python-3.13 \
    # naabu/pcap runtime
    libpcap \
    # Playwright chromium + the glibc libs it dynamically loads
    chromium \
    nss \
    freetype \
    harfbuzz \
    fontconfig \
    font-dejavu \
    libx11 \
    libxcomposite \
    libxdamage \
    libxext \
    libxfixes \
    libxrandr \
    libxkbcommon \
    libdrm \
    mesa-gbm \
    pango \
    cairo \
    at-spi2-core \
    dbus-libs \
    expat \
    alsa-lib \
    # Node.js runtime for the worker engine + the Claude/Playwright CLIs
    nodejs-22 \
    npm

# Claude Agent SDK CLI + Playwright CLI: the worker engine spawns `claude`, and
# the prompts' playwright-cli skill drives the headless browser. Installed here
# (wolfi has npm) so the runtime's `COPY --from=runtime-staging /usr/` brings
# them in — glibc-dynamic has no npm of its own.
RUN npm install -g @anthropic-ai/claude-code@2.1.84 @playwright/cli@0.1.1

# ---------------------------------------------------------------------------
# Stage 4: runtime — minimal glibc-dynamic with binaries + venv copied in.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/glibc-dynamic:latest AS runtime

# glibc-dynamic ships a nonroot user (uid 65532). We need root only to lay down
# files; the image runs as nonroot. The agent pipeline runs unprivileged.
USER root

# Aegis layout.
ENV AEGIS_HOME=/opt/aegis
ENV TOOLS_DIR=/opt/aegis/tools
ENV VENV=/opt/aegis/venv

# 1) Runtime OS closure (libs, nmap, chromium, python3.13, bash/git/curl, …)
#    from the Wolfi runtime-staging stage. These are glibc-ABI by construction.
COPY --from=runtime-staging /usr/ /usr/
COPY --from=runtime-staging /etc/ssl/ /etc/ssl/
COPY --from=runtime-staging /etc/nmap/ /etc/nmap/
COPY --from=runtime-staging /etc/fonts/ /etc/fonts/

# 2) Go tool binaries → /usr/local/bin (single PATH entry).
COPY --from=go-builder /go/bin/ /usr/local/bin/

# 3) Shared Python venv (semgrep, arjun, paramspider, wafw00f, playwright, +
#    the git-clone tools' requirements) and the in-place git-clone tools.
COPY --from=py-builder /opt/aegis/venv/ /opt/aegis/venv/
COPY --from=py-builder /opt/aegis/tools/ /opt/aegis/tools/

# 4) Playwright browser binaries (chromium driver) installed into the venv's
#    cache during py-builder were skipped; we use the apk-provided chromium and
#    point Playwright at it (PLAYWRIGHT_*_EXECUTABLE_PATH below), matching
#    storron. This avoids shipping a second chromium copy.

# Convenience wrappers so skills can invoke the in-place Python tools by name
# from PATH (each runs under the shared venv interpreter).
RUN set -eux; \
    venv_py="$VENV/bin/python3"; \
    make_wrapper() { \
      name="$1"; script="$2"; \
      { \
        printf '#!/bin/sh\n'; \
        printf 'exec "%s" "%s" "$@"\n' "$venv_py" "$script"; \
      } > "/usr/local/bin/$name"; \
      chmod +x "/usr/local/bin/$name"; \
    }; \
    make_wrapper sqlmap   "$TOOLS_DIR/sqlmap/sqlmap.py"; \
    make_wrapper commix   "$TOOLS_DIR/commix/commix.py"; \
    make_wrapper sstimap  "$TOOLS_DIR/SSTImap/sstimap.py"; \
    make_wrapper xsstrike "$TOOLS_DIR/XSStrike/xsstrike.py"; \
    make_wrapper ssrfmap  "$TOOLS_DIR/SSRFmap/ssrfmap.py"; \
    make_wrapper jwt_tool "$TOOLS_DIR/jwt_tool/jwt_tool.py"

# 5) Aegis worker app (Node): dist + prod node_modules + prompts, from node-builder.
#    Kept in the pnpm workspace layout at /opt/aegis/app so the symlinked
#    node_modules resolve. WORKER_ROOT (paths.ts) → apps/worker; PROMPTS_DIR →
#    apps/worker/prompts (both present here).
COPY --from=node-builder /app/node_modules /opt/aegis/app/node_modules
COPY --from=node-builder /app/apps/worker /opt/aegis/app/apps/worker
COPY --from=node-builder /app/package.json /app/pnpm-workspace.yaml /opt/aegis/app/

# 6) Per-tool skills the Claude Agent SDK loads on demand (progressive disclosure).
#    HOME=/tmp + settingSources:["user"] → the SDK discovers ~/.claude/skills.
COPY skills/ /tmp/.claude/skills/

# 7) save-deliverable / generate-totp CLIs that the prompts invoke by name.
RUN ln -sf /opt/aegis/app/apps/worker/dist/scripts/save-deliverable.js /usr/local/bin/save-deliverable && \
    ln -sf /opt/aegis/app/apps/worker/dist/scripts/generate-totp.js /usr/local/bin/generate-totp && \
    chmod +x /opt/aegis/app/apps/worker/dist/scripts/*.js 2>/dev/null || true

# System-level git config (clones/checkouts run as nonroot at runtime).
RUN git config --system user.email "agent@localhost" && \
    git config --system user.name "Aegis Agent" && \
    git config --system --add safe.directory '*'

# Ephemeral working dirs (per-run workdirs are mounted/created at runtime).
RUN mkdir -p /work /tmp/.cache /tmp/.config && \
    chmod 1777 /tmp/.cache /tmp/.config && \
    chown -R 65532:65532 /work /opt/aegis /tmp/.claude

# Build context is the repo root (so apps/ + skills/ are reachable); the
# entrypoint script lives under infra/docker/.
COPY infra/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# PATH: venv first (shared Python tools), then /usr/local/bin (Go + wrappers).
ENV PATH=/opt/aegis/venv/bin:/usr/local/bin:/usr/bin:/bin
ENV HOME=/tmp
ENV XDG_CACHE_HOME=/tmp/.cache
ENV XDG_CONFIG_HOME=/tmp/.config
# Use the apk-provided chromium for Playwright (no second browser download).
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_BROWSERS_PATH=0
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
ENV PYTHONUNBUFFERED=1

# Run unprivileged.
USER 65532
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# Default: run one scan (the per-scan Job command, ADR-051). job-entry.js reads
# the scan params from the environment (AEGIS_*) and runs the pipeline, then exits.
CMD ["node", "/opt/aegis/app/apps/worker/dist/job-entry.js"]
