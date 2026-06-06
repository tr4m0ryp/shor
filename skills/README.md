# skills/ — per-tool usage guides

One folder per offensive binary, each with a `SKILL.md`: YAML frontmatter
(`name`, one-line `description` = when-to-use trigger, tagged with the pipeline
layer `[recon]` / `[static-analysis]` / `[exploit]`) plus a short body —
when to reach for it, key flags, ONE safe rate-limited invocation,
evidence-to-capture, and scope/rate caveats. Progressive disclosure: only the
frontmatter is always in context; the body loads on demand when an agent
escalates to that tool (ADR-035). Preinstalled into the worker image so the
Claude Agent SDK auto-discovers them.

31 skills total: 30 offensive tools (the §5.3 toolkit matrix) + the
`authz-recipe` procedure (the one category with no headless CLI).

## Recon — discovery (pre-recon / recon)

| Skill | Tool |
|---|---|
| [subfinder](subfinder/SKILL.md) | passive subdomain enumeration |
| [dnsx](dnsx/SKILL.md) | bulk DNS resolution + record queries |
| [naabu](naabu/SKILL.md) | fast port discovery (feeds nmap) |
| [nmap](nmap/SKILL.md) | deep service/version + safe NSE |
| [httpx](httpx/SKILL.md) | live HTTP probe + fingerprint |
| [katana](katana/SKILL.md) | web crawl / endpoint discovery |
| [gau](gau/SKILL.md) | historical URLs (Wayback/CC/OTX/URLScan) |
| [waybackurls](waybackurls/SKILL.md) | Wayback Machine URL dump |
| [arjun](arjun/SKILL.md) | active hidden-parameter discovery |
| [paramspider](paramspider/SKILL.md) | archived parameter-URL mining |
| [wafw00f](wafw00f/SKILL.md) | WAF/CDN fingerprinting |
| [ffuf](ffuf/SKILL.md) | HTTP fuzzer (content/param/value; also auth + IDOR) |
| [nuclei](nuclei/SKILL.md) | templated vuln/misconfig scan (also exploit) |

## Static analysis — whitebox, read-only (vuln-analysis)

| Skill | Tool |
|---|---|
| [semgrep](semgrep/SKILL.md) | SAST — taint/pattern rules over the repo |
| [gitleaks](gitleaks/SKILL.md) | secrets in repo + git history |
| [trufflehog](trufflehog/SKILL.md) | secrets with live provider verification |
| [osv-scanner](osv-scanner/SKILL.md) | dependency CVEs via OSV (SCA) |
| [trivy](trivy/SKILL.md) | SCA (npm + NuGet) + IaC/Docker/K8s misconfig + secrets |
| [git-security-history](git-security-history/SKILL.md) | mine repo history for prior security fixes (procedure) |

## Exploit — live PoC (exploitation)

**Injection**

| Skill | Tool |
|---|---|
| [sqlmap](sqlmap/SKILL.md) | SQL injection |
| [commix](commix/SKILL.md) | OS command injection |
| [sstimap](sstimap/SKILL.md) | server-side template injection |
| [nosqli](nosqli/SKILL.md) | NoSQL (MongoDB) injection |

**XSS**

| Skill | Tool |
|---|---|
| [dalfox](dalfox/SKILL.md) | primary XSS scanner + verification |
| [xsstrike](xsstrike/SKILL.md) | context-aware XSS suite (secondary) |
| [kxss](kxss/SKILL.md) | reflected-XSS character triage |

**Auth**

| Skill | Tool |
|---|---|
| [jwt_tool](jwt_tool/SKILL.md) | JWT attacks (alg:none, key confusion, crack) |
| [hydra](hydra/SKILL.md) | network login brute force |
| [generate-totp](generate-totp/SKILL.md) | RFC-6238 TOTP for 2FA test-account login |

**Authz / IDOR / BOLA**

| Skill | Tool |
|---|---|
| [authz-recipe](authz-recipe/SKILL.md) | role x endpoint matrix + A/B replay + ffuf ID enum |

**SSRF**

| Skill | Tool |
|---|---|
| [ssrfmap](ssrfmap/SKILL.md) | SSRF exploitation modules (PoC ceiling) |
| [interactsh-client](interactsh-client/SKILL.md) | OOB/OAST callback confirmation |

**Browser / DOM**

| Skill | Tool |
|---|---|
| [playwright](playwright/SKILL.md) | headless browser — auth flows + XSS execution proof |

## Cross-cutting rules baked into every skill

- **Scope:** act ONLY on hosts/endpoints inside the validated Rules of Engagement;
  re-validate immediately before each network action.
- **No-DoS:** per-host rate limits; each invocation example is throttled.
- **Minimum-impact PoC:** stop at the smallest convincing proof (XBOW pattern);
  no bulk data, no privilege persistence, no pivoting.
- **Secret hygiene:** redact tokens/secrets/PII in evidence; never echo secrets
  into logs or prompt text.
- **Reproducibility:** git-clone tools (sqlmap, commix, SSTImap, nosqli, XSStrike,
  jwt_tool, SSRFmap) are pinned to a `tools.lock` SHA and run in place.
