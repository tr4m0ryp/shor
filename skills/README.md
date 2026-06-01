# skills/ — per-tool usage guides (authored after research)

One folder per tool, each with a `SKILL.md`. Frontmatter (`name`, `description`)
is always in context; the body loads on demand (progressive disclosure) when an
agent escalates to that tool. Preinstalled into the worker image's
`.claude/skills/` so the Claude Agent SDK auto-discovers them.

Planned skills (final set pending `docs/research/`):

```
recon:     httpx · katana · nuclei · ffuf · subfinder · nmap · gau · arjun
static:    semgrep · gitleaks · osv-scanner
injection: sqlmap · commix · sstimap · nosqli
xss:       dalfox · xsstrike · kxss
auth:      jwt_tool · ffuf-login · generate-totp
authz:     ab-replay (IDOR/BOLA recipe) · ffuf-forced-browsing
ssrf:      ssrfmap · interactsh
```

A skill documents: when to reach for it, invocation patterns + key flags, auth
reuse, the evidence/output to capture, safe defaults, and scope/rate guardrails.
Template precedent: storron's `playwright-cli` skill.
