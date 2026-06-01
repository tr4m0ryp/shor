# prompts/ — category system prompts (ported from storron)

Ported from `storron/apps/worker/prompts/` (kept rich and detailed), with two
changes:

1. **Drop the onion variant** (`pre-recon-onion`) and onion template selection.
2. **Add a `<tool_skills>` section** to each category prompt that references the
   relevant skills by name (see `../skills/`).

Files to port: `pre-recon-code`, `recon`, `vuln-{injection,xss,auth,authz,ssrf}`,
`exploit-{injection,xss,auth,authz,ssrf}`, `report-executive`, plus the
`shared/_*.txt` includes. Keep the `@include(...)` mechanism from the
prompt-manager.
