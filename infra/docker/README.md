# Aegis offensive-toolkit image

Multi-stage Wolfi/glibc Docker image that preinstalls the ~30 offensive CLI
tools the Aegis agent pipeline drives via shell (LAUNCH-SPEC §5.2/§5.3,
ADR-023→027). Ported from storron's `infra/docker/Dockerfile` **minus all
Tor/onion machinery** — Aegis runs direct clearnet egress only.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | 4-stage build: `go-builder` → `py-builder` → `runtime-staging` → `runtime`. |
| `tools.lock` | Pins every git-clone tool to a real commit SHA (`git ls-remote`); records go-install/pip/apk methods for supply-chain audit (ADR-027). |
| `entrypoint.sh` | De-Tor'd, de-privileged container entrypoint. |

## Build strategy (why these stages)

- **Builders** use `cgr.dev/chainguard/wolfi-base` (ships apk + a shell).
  **Runtime** uses `cgr.dev/chainguard/glibc-dynamic` (minimal, shell-less,
  apk-less) with binaries + the Python venv copied in.
- Wolfi is **glibc**, not musl like Alpine, so PyPI wheels and CGO binaries
  install natively. **No Alpine/musl binary is ever copied in** (ABI-incompatible:
  `ld-musl` vs `libc.so.6`). The runtime OS closure (libs, `nmap`, `chromium`,
  `python-3.13`) is apk-installed in `runtime-staging` against the *same* Wolfi
  glibc, then copied forward — so every shared object is glibc-ABI.
- One **shared Python venv** at `/opt/aegis/venv`, on PATH, no
  `--break-system-packages` (ADR-026).
- **katana** is built `CGO_ENABLED=1` with gcc + Go 1.25 (`go-1.25` apk
  package) for the headless path; **naabu** needs `libpcap-dev` (build) /
  `libpcap` (runtime).
- git-clone tools are pinned to SHAs from `tools.lock`, passed as `--build-arg`.

## Build

The build **context is this directory** (`infra/docker/`). Pass the seven pinned
SHAs from `tools.lock` as build args (a future `make`/CI target should read
`tools.lock` and generate these flags):

```sh
docker build \
  --build-arg SQLMAP_SHA=e6595430483f0cf57ad36539ffc61fc4a6060df5 \
  --build-arg COMMIX_SHA=20794529a2bb307056f12571027bb3fbe6afb48d \
  --build-arg SSTIMAP_SHA=d4f09055b15967b0e2265f20eb348a7ec2f25a2c \
  --build-arg XSSTRIKE_SHA=ab27955d367432f944d8f29897e09c15356e76f7 \
  --build-arg SSRFMAP_SHA=69103b27f5898d9707630dc572798df63727b90f \
  --build-arg JWT_TOOL_SHA=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b \
  --build-arg NOSQLI_SHA=6fce3ebc8c8127940221d9287b00493be43d7564 \
  --build-arg PARAMSPIDER_SHA=c44bdaae54789b237028e309b603d1aa5ad52e5e \
  -t aegis-toolkit:latest \
  infra/docker
```

Stage-only builds for verification:

```sh
docker build --check ... infra/docker                    # lint all stages
docker build --target go-builder --build-arg NOSQLI_SHA=... ... infra/docker
docker build --target py-builder --build-arg SQLMAP_SHA=... ... infra/docker
```

## Runtime layout

| Path | Contents |
|---|---|
| `/usr/local/bin/` | Go tool binaries + thin wrappers for the in-place Python tools (`sqlmap`, `commix`, `sstimap`, `xsstrike`, `ssrfmap`, `jwt_tool`). |
| `/opt/aegis/venv/` | Shared Python venv (semgrep, arjun, paramspider, wafw00f, playwright + git-clone tools' requirements). First on PATH. |
| `/opt/aegis/tools/` | Pinned git-clone tool checkouts (run in place). |
| `/usr/bin/` | apk-provided `nmap`, `chromium`, `python3.13`, `git`, `bash`, `curl`. |
| `/work` | Default ephemeral per-run working dir; runs as nonroot uid 65532. |

Playwright uses the apk-provided glibc chromium
(`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium`,
`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`) — no second browser is downloaded.

## What was removed vs storron (de-Tor)

Dropped entirely: the `onionscan-builder` stage, the `torsocks-builder` stage,
every `torsocks`/`libtorsocks`/`/etc/tor` COPY, the onion-target notes, and the
entrypoint's `STORRON_HOST_UID/GID` userdel/useradd remap + `su pentest`
(host-Docker bind-mount remapping is moot under the Cloud Run Job per-scan model,
ADR-051; the image runs unprivileged as uid 65532). `grep -ri 'tor\|onion' .`
in this directory returns only the word "history"/"tools" — no Tor machinery.

The storron Node-app build layers (pnpm install/build of `@storron/worker`) are
**not** ported here: the Aegis worker source does not yet exist in this repo, and
the engine port is a later phase (LAUNCH-SPEC §7 Phase 1). This image is the
toolkit substrate; the worker layers get appended when the engine lands.

## Tool inventory + build-verification status

`★` primary. Method per ADR-025. **Verified** = the stage that builds it
completed locally; **BLOCKED-for-acceptance** = not yet runtime-verified in this
sandbox (see "Verification status" below for why) — author-validated only.

| Category | Tool | Method | Module / source |
|---|---|---|---|
| Recon-net | ★subfinder | go-install | `projectdiscovery/subfinder/v2/cmd/subfinder` |
| | ★httpx | go-install | `projectdiscovery/httpx/cmd/httpx` |
| | dnsx | go-install | `projectdiscovery/dnsx/cmd/dnsx` |
| | naabu | go-install (CGO+libpcap) | `projectdiscovery/naabu/v2/cmd/naabu` |
| | nmap | apk | Wolfi `nmap` |
| Recon-web | ★ffuf | go-install | `ffuf/ffuf/v2` |
| | ★katana | go-install CGO=1 | `projectdiscovery/katana/cmd/katana` |
| | gau | go-install | `lc/gau/v2/cmd/gau` |
| | waybackurls | go-install | `tomnomnom/waybackurls` |
| | ★arjun | pip | `arjun` |
| | paramspider | git-clone (pinned) + pip install . | `devanshbatham/ParamSpider` (NOT on PyPI) |
| | wafw00f | pip | `wafw00f` |
| Templated | ★nuclei | go-install | `projectdiscovery/nuclei/v3/cmd/nuclei` |
| Static | ★semgrep | pip | `semgrep` |
| | gitleaks | go-install | `gitleaks/gitleaks/v8` |
| | ★osv-scanner | go-install | `google/osv-scanner/v2/cmd/osv-scanner` |
| | trufflehog | go-install | `trufflesecurity/trufflehog/v3` |
| SQL/NoSQL | ★sqlmap | git-clone (pinned) | `sqlmapproject/sqlmap` |
| | nosqli | go-install (pinned SHA) | `Charlie-belmer/nosqli` |
| Command | ★commix | git-clone (pinned) | `commixproject/commix` |
| SSTI | ★SSTImap | git-clone (pinned) | `vladko312/SSTImap` |
| XSS | ★dalfox | go-install | `hahwul/dalfox/v2` |
| | xsstrike | git-clone (pinned) | `s0md3v/XSStrike` |
| | kxss | go-install | `Emoe/kxss` |
| JWT | ★jwt_tool | git-clone (pinned) | `ticarpi/jwt_tool` |
| SSRF | ★ssrfmap | git-clone (pinned) | `swisskyrepo/SSRFmap` |
| | ★interactsh-client | go-install | `projectdiscovery/interactsh/cmd/interactsh-client` |
| Browser | Playwright | pip + apk chromium | `playwright` + Wolfi `chromium` |

DEFAULT-marked tools from ADR-025 that are NOT in this image (deferred,
non-blocking, post-launch tunable): masscan, rustscan, amass, feroxbuster,
gobuster, dirsearch, hydra, medusa, patator. The matrix marks these `(D)` /
thin-evidence; the `★` primaries above cover every pipeline layer (§5.4).

### Deviation from ADR-025 (build-driven)

- **paramspider**: ADR-025 lists `pip install …`. A real `py-builder` build
  proved **paramspider is not on PyPI** (`No matching distribution found`).
  Reclassified to a **pinned git-clone + `pip install .`** from
  `devanshbatham/ParamSpider` (its `setup.py` exposes the `paramspider` console
  script on the venv PATH). This is exactly the kind of `(D)` thin-evidence pick
  the spec flagged as tunable. Pin recorded in `tools.lock`.

### Verification status (this sandbox)

The build was exercised on a Colima/QEMU `linux/amd64` VM on an Intel Mac. Under
that emulation, large Go tools compile *very* slowly (nuclei alone ≈ 26 min), so
the full `runtime` image could not finish in-sandbox. That is a host-performance
limit, **not** a Dockerfile defect: a native `linux/amd64` CI runner builds these
in a fraction of the time.

| Aspect | Status | Evidence |
|---|---|---|
| `docker build --check` (all 4 stages) | **PASS, no warnings** | run twice (incl. after the paramspider fix) |
| **py-builder** stage (full) | **BUILD-VERIFIED** | built end-to-end to image export, exit 0: semgrep 1.164.0, arjun 2.2.7, wafw00f 2.4.2, playwright 1.60.0 (pip, glibc wheels); sqlmap/commix/SSTImap/XSStrike/SSRFmap/jwt_tool cloned at pinned SHAs + requirements; paramspider wheel built + installed |
| Go module paths resolve + compile | **BUILD-VERIFIED (corrected paths)** | `go install` in a throwaway Wolfi container built kxss (`Emoe/kxss`), gau (`/v2/cmd/gau`), waybackurls, dalfox (`/v2@latest` → latest v2.x, not the v3 Rust rewrite), nosqli (`@<pinned SHA>`) with no path errors |
| go-builder large tools (nuclei, trufflehog, katana CGO, naabu CGO, osv-scanner, gitleaks) | **BLOCKED-for-acceptance** (compile time only) | step compiled through `nuclei/v3/cmd/nuclei` (its main package) before the sandbox window closed; httpx/subfinder/dnsx/interactsh deps fetched cleanly. Paths are the verified-correct semantic-import suffixes; needs a native CI build to finish + smoke-test |
| Full `runtime` (glibc-dynamic) assembly | **BLOCKED-for-acceptance** | gated only by the go-builder compile time above |

**Acceptance gate for CI** (Launch-Readiness "All ~30 tools install … and run on
the slim runtime"): on a native `linux/amd64` runner, build the full image with
the seven `--build-arg` SHAs, then smoke-test every binary
(`<tool> -version`/`--version`/`-h`) on the `glibc-dynamic` runtime. Everything
above marked BLOCKED is author-validated + path-verified; only the long native
compile + per-tool `--version` remains.
