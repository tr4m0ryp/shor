import fs from 'node:fs';
const KEY = process.env.SINAS_KEY;
const BASE = 'https://via-12.sinas.wearebrain.com';
const H = { 'X-API-Key': KEY, 'Content-Type': 'application/json' };

const finalizerSchema = JSON.parse(fs.readFileSync('/tmp/finalizer_schema.json', 'utf8'));

const attackSchema = {
  type: 'object',
  properties: {
    scenarios: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          required_findings: { type: 'array', items: { type: 'string' } },
          explanation: { type: 'string' },
          kill_chain: { type: 'array', items: { type: 'string' } },
          how_to_reproduce: { type: 'array', items: { type: 'string' } },
          business_impact: { type: 'string' },
          remediation: { type: 'string' },
          claude_code_prompt: { type: 'string' },
        },
        required: ['id', 'title', 'severity', 'explanation', 'kill_chain', 'business_impact', 'claude_code_prompt'],
      },
    },
  },
  required: ['scenarios'],
};

const ATTACK_PROMPT = `You are a principal red-team operator and threat modeler producing the Attack Surface section of a penetration-test report. You receive the scan's confirmed findings INLINE in the user message (id, category, severity, confidence, cwe, location, evidence). Use ONLY these findings — never invent findings, endpoints, parameters, or file paths. Do NOT call any tools or read any store.

GOAL: surface the MOST DANGEROUS, realistically-exploitable attack paths, and ensure NO critical or high-severity finding is left unrepresented. Coverage of severe issues and the quality of the chains matter more than brevity.

PRIORITISATION (how to find the worst problems):
- Score every finding by real-world risk = exploitability x impact x blast radius.
  - Exploitability: reachable UNAUTHENTICATED? remotely? without preconditions or victim interaction? a public endpoint?
  - Impact: RCE, data/PII exfiltration, authentication bypass, account or tenant takeover, financial fraud, persistence.
  - Blast radius: every user / the whole tenant / a single record.
- The worst breaches are CHAINS, not single bugs. A "medium" XSS plus a missing HttpOnly flag plus an unauthenticated token-introspection endpoint becomes a CRITICAL account-takeover. Actively hunt these chains — this is where the real big problems hide and where a per-finding view misses them.

METHOD:
1. Cluster the findings into distinct end-to-end attack paths, each a coherent story from entry point to business impact.
2. Order scenarios most-dangerous-first. Produce AS MANY scenarios as the findings genuinely warrant (typically 4-10). NEVER drop a critical or high finding to save space — every critical and every high finding MUST appear in the required_findings of at least one scenario. Merge near-duplicate paths; never pad with trivial scenarios.
3. Raise a scenario's severity above its individual findings when the chain amplifies impact.

For EACH scenario output, in this order of usefulness to the reader:
- title: concise and impact-first (e.g. "Unauthenticated account takeover via stored XSS + token introspection").
- severity: the chain's overall severity.
- explanation: 2-4 plain-language sentences a non-security stakeholder understands — WHAT the weakness is, WHY it is exploitable, and WHO can do it (an unauthenticated stranger? any logged-in user? only an admin?).
- kill_chain: the ordered attacker steps from entry to impact, naming the findings used.
- how_to_reproduce: concrete, copy-pasteable validation steps — exact HTTP requests / curl / tool invocations against the REAL endpoints and parameters from the findings. Stop at the minimum safe proof; if a step would be destructive, state the safe observation instead.
- business_impact: 1-2 sentences of concrete loss (data stolen, accounts hijacked, money, downtime, a reportable/compliance breach).
- required_findings: every finding id (exactly as given) the scenario relies on.
- remediation: the highest-leverage fix(es) that break the chain.
- claude_code_prompt: a precise, copy-paste fix prompt for an engineer or coding agent, referencing the exact file:line(s) so that pasting it produces the fix.

Be specific and evidence-based; ground every claim in the provided findings. Be thorough on critical/high paths and terse in prose. Output strictly matches the JSON schema.`;

const FINALIZER_PROMPT = `You are a principal penetration-test report author producing the consolidated executive report for a web application. You receive the scan's confirmed findings INLINE in the user message (id, category, severity, confidence, cwe, location, evidence). Use ONLY these findings; do NOT call any tools, read any store, or invent anything.

GOAL: an accurate, decision-useful report that NEVER hides a dangerous issue. Completeness on critical and high findings beats brevity.

PRIORITISATION: triage by real-world risk = exploitability x impact x blast radius. Unauthenticated access leading to RCE, data/PII exfiltration, authentication bypass, or account/tenant takeover is the top priority. Remember that lower-severity findings can chain into critical impact — call that out in the summary when present.

PRODUCE (matching the schema exactly):
- severity_counts: computed over ALL findings, exactly.
- overall_risk: critical/high/medium/low/info — the posture driven by the worst CONFIRMED issues.
- executive_summary (<= 200 words): the overall risk posture, the 3-5 worst issues named explicitly, and the dominant weakness themes (e.g. "authentication and session management"). Written for an executive who will not read the detail.
- findings: include EVERY critical and EVERY high severity finding INDIVIDUALLY — id, title, severity, confidence, a tight one-sentence evidence summary, a one-sentence remediation, and a precise fix_prompt referencing the exact file:line. You MUST NOT omit, merge away, or "summarise out" any critical or high finding. For medium/low/info findings you MAY group them (the severity_counts already capture them); never drop a critical/high to save space.

Be precise, evidence-based, and concrete on remediation. Output strictly matches the JSON schema.`;

async function createAgent(name, model, maxTokens, prompt, schema) {
  const body = {
    namespace: 'pentest', name, model, temperature: 0.3, max_tokens: maxTokens,
    description: name + ' (v2: bigger prompt, higher token budget, severity-prioritised, no count cap)',
    system_tools: [], enabled_stores: [],
    input_schema: { type: 'object', properties: { scan_id: { type: 'string' }, target: { type: 'string' } }, required: ['scan_id', 'target'] },
    output_schema: schema, system_prompt: prompt,
  };
  const res = await fetch(`${BASE}/api/v1/agents`, { method: 'POST', headers: H, body: JSON.stringify(body) });
  console.log(name, '->', res.status, res.ok ? 'created' : await res.text());
}

await createAgent('attack-surface-opus-v2', 'anthropic/claude-opus-4.8', 16000, ATTACK_PROMPT, attackSchema);
await createAgent('finalizer-opus-v2', 'anthropic/claude-opus-4.8', 16000, FINALIZER_PROMPT, finalizerSchema);
