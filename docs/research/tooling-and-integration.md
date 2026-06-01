# Research findings — perfect tools + best-fit integration designs

First research pass (2026-06-01). Sources at the bottom. Confidence: high on the
integration model and the core toolkit; medium where a category has no de-facto
CLI (authz). A deeper per-category pass can extend each section.

---

## 1. Integration landscape — how everyone wires LLM ↔ tools

The field splits into **two schools** (PentestMCP survey framing):

- **MCP-based** — tools exposed as typed MCP functions an agent calls.
  Examples: **HexStrike AI** (150+ tools), Kali-MCP, PentestMCP.
- **Direct tool-calling** — the agent runs tools via shell/code directly.
  Examples: **PentestGPT**, **CAI**, **Strix**.

**Skills and MCP are orthogonal, not competing** (Anthropic's own framing):

- A **Skill** is *procedural knowledge* — "how to use this tool / follow this
  procedure," file-based, loaded on demand, can carry runnable scripts. It does
  **not** reach external systems at runtime.
- **MCP** is *connectivity* — reaching an external DB, repo, or live service.

### What this means for Aegis (decision-grade)

Our chosen model — **rich prompt + per-tool skill + preinstalled binary, run via
shell** — is exactly the **direct-tool-calling school with Skills as the
procedural layer**. The research confirms this is a first-class, proven pattern,
not a compromise. Concretely:

- **Skills** carry per-tool how-to (the user's exact ask). ✅ keep.
- **Shell** executes the preinstalled binary. ✅ keep (no MCP needed to run sqlmap).
- **MCP is reserved for connectivity**, where it genuinely fits: the **GitHub repo
  connection** and the **findings datastore** — not for running scanners.
- **HexStrike AI** is the reference implementation of the *MCP-everything* end of
  the spectrum. We can (a) borrow its tool taxonomy + `@mcp`-decorator wrapper
  pattern, and (b) optionally bolt it on later as a typed tool layer — but it is
  **not required**, and it carries baggage: it has been **abused in the wild**
  (HexStrike-driven Citrix zero-day exploitation), underscoring that guardrails
  must live at our boundary regardless.

### Findings model to emulate — XBOW

XBOW (currently #1 on HackerOne) **validates each finding by running a harmless
PoC under an automatic safety layer**, then emits a **reproducible exploit script +
remediation**. This is the gold standard for our ADR-005 structured findings:
finding = {category, CWE, severity, evidence, *safe PoC*, repro steps, status}.
Strix follows the same "validate via real PoC" principle.

---

## 2. Confirmed toolkit (per category)

Cross-checked against HexStrike's 150-tool taxonomy + per-tool maintenance checks.
`★` = primary/default for that job.

| Layer / category | Confirmed tools | Notes |
|---|---|---|
| **Recon — network** | ★nmap, masscan/rustscan, ★subfinder, amass, ★httpx, dnsx, naabu | httpx+subfinder+dnsx is the standard PD chain |
| **Recon — web/content** | ★ffuf, feroxbuster, gobuster, dirsearch, ★katana, gau, waybackurls, ★arjun, paramspider, wafw00f | ffuf primary; arjun/paramspider for params |
| **Templated scan** | ★nuclei | has experimental `-ai` flag (dynamic payload/template gen) — relevant to our AI context |
| **Static (whitebox)** | ★semgrep, gitleaks, ★osv-scanner, trufflehog | semgrep per-category rulesets; osv-scanner for deps |
| **Injection — SQL/NoSQL** | ★sqlmap, nosqli | sqlmap is undisputed; nosqli (Go) for NoSQL |
| **Injection — command** | ★commix | de-facto standard |
| **Injection — SSTI** | ★SSTImap | py3, interactive, maintained — beats abandoned py2 tplmap |
| **XSS** | ★dalfox, xsstrike, kxss | dalfox actively maintained (Go v2 branch backported; Rust rewrite underway); kxss for fast reflection triage |
| **Auth — JWT** | ★jwt_tool | standard for alg-none / key-confusion / secret-crack |
| **Auth — credential** | ★ffuf (HTTP), hydra, medusa, patator | ffuf for HTTP login; hydra for protocol logins |
| **Authz / IDOR / BOLA** | **no drop-in CLI** | Autorize/AuthMatrix are Burp extensions → model as an **A/B session-replay + authorization-matrix recipe** skill driving curl/Playwright (see §3) |
| **SSRF** | ★ssrfmap, ★interactsh | ssrfmap takes a raw request + param; interactsh for OOB/OAST confirmation |
| **Browser / DOM** | Playwright (headless) | confirm XSS execution + drive auth flows; HexStrike calls this a "Burp alternative" browser agent |

**Net change from the pre-research list:** all originals confirmed. Additions worth
considering — **paramspider** (alongside arjun), **wafw00f** (WAF fingerprint),
**feroxbuster** (recursive content discovery), and **nuclei `-ai`**.

---

## 3. The authz gap — design, not a tool

Broken Access Control is **#1 OWASP 2021 and 2025**, but there is **no headless CLI
equivalent of Burp's Autorize**. The winning design (per Equixly's authorization-
matrix work) is:

1. Build a **role × endpoint matrix** from recon (who *should* access what).
2. **A/B replay**: capture a request as the owning/high-priv identity, replay it
   verbatim with a low-priv / other-user session, diff responses.
3. Enumerate object IDs (ffuf + `seq`/UUID lists) for IDOR/BOLA; verify each 200
   actually leaks another identity's object.

→ Aegis ships this as a **recipe skill** (not a binary) driving curl/Playwright +
ffuf. This is the one category where the "skill = procedure" model carries the
whole weight.

---

## 4. Implications for our decisions

- **ADR-002 validated.** Direct-tool-calling + Skills is a proven school; keep it.
- **MCP scoped.** Use MCP only for *connectivity* (GitHub repo, datastore) per the
  Skills-vs-MCP split — not for running scanners. Revisit a HexStrike-style typed
  tool layer only if we want cross-product reuse.
- **ADR-005 sharpened.** Adopt the XBOW pattern: every finding carries a **safe,
  reproducible PoC** validated under a safety layer; that PoC + its structured
  record is what powers history and scan-to-scan diffs.
- **Guardrails are non-negotiable at our boundary.** HexStrike's real-world abuse
  shows prompt-level scope rules aren't enough — enforce in-scope-only + rate
  limits + redaction in code (egress proxy / tool wrapper), not just the prompt.

## 5. Still open (next research pass)

- Per-tool install on Wolfi/glibc minimal image (which need git-clone vs go/pip).
- Whether to vendor/borrow from HexStrike's wrapper layer vs author skills fresh.
- Datastore + scheduler specifics for re-scans and diffs (Temporal schedule vs cron).
- Exact finding JSON schema (model on XBOW output + OWASP/CWE fields).

---

## Sources

- [PentestMCP: A Toolkit for Agentic Penetration Testing (arXiv)](https://arxiv.org/pdf/2510.03610)
- [HexStrike AI (GitHub)](https://github.com/0x4m4/hexstrike-ai) · [Check Point: HexStrike-AI & zero-day exploitation](https://blog.checkpoint.com/executive-insights/hexstrike-ai-when-llms-meet-zero-day-exploitation/) · [SC Media: HexStrike abused for Citrix](https://www.scworld.com/news/hexstrike-ai-pentesting-framework-abused-to-exploit-citrix-vulnerabilities)
- [Strix — open-source AI hackers (GitHub)](https://github.com/usestrix/strix)
- [PentAGI (GitHub)](https://github.com/vxcontrol/pentagi)
- [XBOW — web app pentest at AI speed](https://xbow.com/pentest)
- [Anthropic: Skills explained (vs MCP, prompts, subagents)](https://claude.com/blog/skills-explained) · [MCP vs Agent Skills: different, not competing](https://dev.to/phil-whittaker/mcp-vs-agent-skills-why-theyre-different-not-competing-2bc1)
- [SSTImap (GitHub)](https://github.com/vladko312/SSTImap) · [tplmap (GitHub)](https://github.com/epinna/tplmap)
- [Dalfox (GitHub)](https://github.com/hahwul/dalfox) · [Dalfox: open-source XSS scanner (Help Net Security)](https://www.helpnetsecurity.com/2025/02/26/dalfox-open-source-xss-scanner/)
- [SSRFmap (GitHub)](https://github.com/swisskyrepo/SSRFmap)
- [Equixly: API authorization matrix — automated BOLA testing](https://equixly.com/blog/2025/10/07/authorization-matrix/) · [PortSwigger: testing for IDORs](https://portswigger.net/burp/documentation/desktop/testing-workflow/access-controls/testing-for-idors)
- [AI pentesting agents 2026 — 39+ tools tested (AppSec Santa)](https://appsecsanta.com/research/ai-pentesting-agents-2026)
