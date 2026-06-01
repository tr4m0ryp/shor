# Aegis (codename — rename freely)

**An enterprise-flavored, autonomous AI pentester for web apps and APIs.**
Built for a hackathon as the next-generation successor to the `storron` reference
project (`/Users/macbookpro/projects/hackatron/storron`, used as a code/prompt
source only — never modified).

> **Status: DESIGN + RESEARCH phase.** This repo currently holds architecture
> decisions and research, not implementation. Code is ported in only after the
> tool/integration research below converges. See `docs/`.

## What makes it different from storron

1. **No Tor / onion egress.** The entire onion integration is dropped — direct
   clearnet only (optionally a normal HTTP proxy).
2. **Tool-driven agents.** Each OWASP category drives the dedicated, industry
   tools common to that area (sqlmap, dalfox, …), preinstalled in the image.
3. **Rich prompt + per-tool skills.** Keep storron's detailed category system
   prompts for strategy; each tool gets its own *skill* (progressive-disclosure
   usage guide) loaded on demand.
4. **Company surface.** Connect a repository, register target sites, schedule
   re-scans, and browse run history + scan-to-scan diffs. Single-tenant,
   self-hosted. Reuses storron's web dashboard UI.

## Layout

```
docs/architecture.md      Locked design decisions (the saved discussion)
docs/research-plan.md     Open questions research must answer
docs/decisions.md         ADR-style decision log
docs/research/            Research findings (perfect tools + best-fit designs)
skills/                   Per-tool skill guides (authored after research)
prompts/                  Category system prompts (ported from storron)
apps/                     web / worker / cli (ported + de-Tor'd after research)
```
