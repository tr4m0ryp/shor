const KEY = process.env.SINAS_KEY;
const BASE = 'https://via-12.sinas.wearebrain.com';
const H = { 'X-API-Key': KEY, 'Content-Type': 'application/json' };

const schema = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          evidence: { type: 'string' },
          missing_defense: { type: 'string' },
          remediation: { type: 'string' },
          safe_poc: { type: 'string' },
          repro_steps: { type: 'array', items: { type: 'string' } },
        },
        required: ['id'],
      },
    },
  },
  required: ['findings'],
};

const prompt = `You are a penetration-test report editor. You receive raw findings INLINE (often verbose, with cramped inline markdown like "**Summary:** - **Vulnerable location:** ..."). For EACH finding, REWRITE its text fields for clarity and readability WITHOUT changing the technical meaning, severity, location, or the substance of the evidence. Use ONLY the data given; do not call tools, do not invent, do not drop or soften findings.

For each finding output (keyed by the SAME id, unchanged):
- title: a concise, specific, human-readable title (e.g. "Login endpoint has no brute-force protection").
- evidence: a clean, tight account of WHAT was found and the proof. Use light, correct markdown: at most one or two short bold labels, short sentences or "- " bullets, and REAL fenced code blocks for any request/command/payload — use \`\`\`http for HTTP requests, \`\`\`bash for shell, \`\`\`python/\`\`\`json as appropriate. NEVER cram code or long chains of ** inline. Keep it to a few sentences/bullets.
- missing_defense: one concise sentence naming the absent control.
- remediation: one or two concise sentences describing the concrete fix.
- safe_poc: the minimal proof — a SINGLE fenced code block when it is a command/request, otherwise one short sentence.
- repro_steps: an ordered list of short, concrete steps (commands/requests in fenced blocks where helpful).

Preserve every file:line reference, endpoint, URL, parameter name, CWE id, and payload EXACTLY as given. Keep each finding's id unchanged. Be faithful, structured, and concise. Output strictly matches the schema and includes EVERY finding you were given.`;

const body = {
  namespace: 'pentest', name: 'findings-improver', model: 'anthropic/claude-sonnet-4.6',
  temperature: 0.2, max_tokens: 16000, system_tools: [], enabled_stores: [],
  description: 'Rewrites raw findings into clean, well-formatted evidence/remediation/repro (proper bold + fenced bash/http). Sonnet 4.6, inline, no tools.',
  input_schema: { type: 'object', properties: { scan_id: { type: 'string' } }, required: ['scan_id'] },
  output_schema: schema, system_prompt: prompt,
};
const res = await fetch(`${BASE}/api/v1/agents`, { method: 'POST', headers: H, body: JSON.stringify(body) });
console.log('findings-improver ->', res.status, res.ok ? 'created' : await res.text());
