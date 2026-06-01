export const meta = {
  name: 'research-finalize',
  description: 'Self-driving /research: triggers Claude deep-research on the open items, folds in the cloud report + all Aegis docs + storron source, resolves every open item, and writes the launch-ready spec.',
  phases: [
    { title: 'DeepResearch', detail: 'trigger base deep-research on the remaining open items, as input' },
    { title: 'Ground', detail: 'read the cloud report + all design docs + storron source' },
    { title: 'Resolve', detail: 'turn every open item into a final decision' },
    { title: 'Finalize', detail: 'write LAUNCH-SPEC.md' },
  ],
}

const DOCS = '/Users/macbookpro/projects/hackatron/aegis/docs'
const STORRON = '/Users/macbookpro/projects/hackatron/storron'

// ─── Phase 1: trigger Claude's base deep-research as an INPUT (nested workflow). ───
// Scoped to the items the running cloud deep-research does NOT cover, so we add new
// signal instead of duplicating it. Its output is fed into Resolve/Finalize below.
phase('DeepResearch')
const REMAINING_BRIEF =
  `Cited, decision-grade research for "Aegis", an autonomous multi-tenant AI web-pentest platform (reuses modules ` +
  `from the single-user reference "storron"). Do NOT ask clarifying questions; assume sensible defaults and state them. ` +
  `Cover, each with a concrete recommendation + trade-offs:\n` +
  `1. INSTALL METHODS for the offensive toolkit on a minimal glibc (Chainguard Wolfi) Docker image — for each of sqlmap, ` +
  `commix, SSTImap, nosqli, dalfox, xsstrike, kxss, jwt_tool, ssrfmap, interactsh-client, ffuf, nuclei, httpx, katana, ` +
  `subfinder, arjun, semgrep, gitleaks, osv-scanner: is it reliably installable via go install vs pip vs git-clone, ` +
  `current maintenance status, and any glibc/Wolfi gotchas.\n` +
  `2. HexStrike-AI: borrow/vendor its MCP wrapper layer (150+ tools) vs author per-tool Claude skills fresh — pros, cons, ` +
  `and fit with the Claude Agent SDK for an autonomous pentest agent.\n` +
  `3. BEST FINDING/VULNERABILITY JSON SCHEMA for ranked web-app vulns that supports scan-to-scan diffing and history — ` +
  `compare SARIF, DefectDojo's model, OWASP/CWE fields; which fields make findings stably diffable across scans.\n` +
  `4. Verify the integration model "rich system prompt + per-tool skill (progressive disclosure) + shell execution, MCP only ` +
  `for connectivity" against current best practice for agentic pentest (PentestGPT, Strix, CAI, HexStrike, XBOW).\n` +
  `End with concrete recommendations for each. Cite sources.`

let deepResearch
try {
  deepResearch = await workflow('deep-research', REMAINING_BRIEF)
} catch (e) {
  deepResearch = 'deep-research sub-workflow failed: ' + (e && e.message ? e.message : String(e))
}
const deepResearchText =
  typeof deepResearch === 'string' ? deepResearch : JSON.stringify(deepResearch, null, 2)

// ─── Phase 2: Ground — read the cloud report + local docs + storron (storron-lens). ───
phase('Ground')
const grounders = [
  {
    label: 'design-digest',
    prompt:
      `Read these files IN FULL and produce an exhaustive structured digest:\n` +
      `- ${DOCS}/architecture.md\n- ${DOCS}/decisions.md\n- ${DOCS}/research-plan.md\n` +
      `- ${DOCS}/project-model.md\n- ${DOCS}/research/output-schema.md\n- ${DOCS}/research/storron-baseline.md\n\n` +
      `Output: (1) the LOCKED decisions (ADR id + one line each), (2) EVERY open/unresolved item VERBATIM ` +
      `(OPEN sections + research-plan A–D), (3) the storron reuse/port map.`,
  },
  {
    label: 'cloud-digest',
    prompt:
      `Read ${DOCS}/research/cloud-and-multitenancy.md IN FULL — the cloud/multi-tenancy deep-research output. ` +
      `Digest the CHOSEN recommendation for each of: multi-tenant auth, per-user secrets, run isolation, GCP compute, ` +
      `Temporal placement, Google database, dashboard hosting, guardrails — plus the reference architecture + rough cost. ` +
      `Quote the selected option, not the rejected ones. If the file does not exist, return exactly "CLOUD REPORT MISSING".`,
  },
  {
    label: 'tools-digest',
    prompt:
      `Read ${DOCS}/research/tooling-and-integration.md IN FULL. Output the FINAL per-category toolkit, the integration ` +
      `model, and the per-tool skill list. Flag any tool whose install method is still unspecified.`,
  },
  {
    label: 'storron-portcheck',
    prompt:
      `Inspect storron at ${STORRON} (READ-ONLY — never modify). Confirm port feasibility of the reuse targets: ` +
      `apps/worker/src/ai/claude-executor, services/prompt-manager, prompts/, session-manager/agents, apps/web, the Temporal ` +
      `workflow scaffolding, apps/web/src/api/uploads. For each: confirm it exists, note what must change to remove Tor and to ` +
      `fit multi-tenant + GCP, and flag gotchas. Use ls/grep/read.`,
  },
]
const [design, cloud, tools, portcheck] = await parallel(
  grounders.map(g => () => agent(g.prompt, { label: g.label, phase: 'Ground' })),
)

// ─── Phase 3: Resolve — every open item becomes a final decision. ───
phase('Resolve')
const resolution = await agent(
  `You are finalizing the Aegis design for launch. Using the inputs below, resolve EVERY open/unresolved item into a final, ` +
  `concrete decision with a one-line rationale. Leave NOTHING unresolved; where evidence is thin pick a sensible default and ` +
  `mark it (DEFAULT). Prefer the freshly-researched + cloud recommendations over older assumptions when they conflict.\n\n` +
  `## FRESH DEEP-RESEARCH (install methods, schema, HexStrike, integration)\n${deepResearchText}\n\n` +
  `## CLOUD DEEP-RESEARCH\n${cloud}\n\n## DESIGN (decisions + open items + reuse map)\n${design}\n\n` +
  `## TOOLS\n${tools}\n\n## STORRON PORT CHECK\n${portcheck}\n\n` +
  `Output an ADR-style list: each open item → FINAL decision + rationale.`,
  { label: 'resolve-open-items', phase: 'Resolve' },
)

// ─── Phase 4: Finalize — write the launch-ready spec. ───
phase('Finalize')
const summary = await agent(
  `Write the launch-ready specification for Aegis as one cohesive markdown document, then save it.\n\n` +
  `## RESOLVED DECISIONS\n${resolution}\n\n## FRESH DEEP-RESEARCH\n${deepResearchText}\n\n## CLOUD\n${cloud}\n\n` +
  `## DESIGN\n${design}\n\n## TOOLS\n${tools}\n\n## PORT CHECK\n${portcheck}\n\n` +
  `The document MUST contain, in this order:\n` +
  `1. Executive summary (what Aegis is, one paragraph).\n` +
  `2. Final reference architecture — compute, Temporal, database, auth, secrets, egress — as a text diagram + prose.\n` +
  `3. Multi-tenancy: OAuth, per-user config/secrets, per-user run isolation.\n` +
  `4. Project model (tenant→project→codebase-version→scan) + data schema.\n` +
  `5. Agent pipeline + per-category toolkit (with install method per tool) + per-tool skills + guardrails.\n` +
  `6. Output schema + the remediation ("fix") Claude Code prompt.\n` +
  `7. Phased implementation/build plan — what to port from storron first, what to build new, in order.\n` +
  `8. Launch-readiness checklist (each item checkable).\n\n` +
  `Save it to ${DOCS}/LAUNCH-SPEC.md with the Write tool (overwrite if present). Return a 6-line summary + confirm the path.`,
  { label: 'write-launch-spec', phase: 'Finalize' },
)

return { launchSpec: `${DOCS}/LAUNCH-SPEC.md`, summary, resolutionPreview: resolution.slice(0, 800) }
