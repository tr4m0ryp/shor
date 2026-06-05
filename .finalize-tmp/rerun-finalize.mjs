/**
 * Off-pipeline finalize rerun for scan aee232e8-07ef-42dd-a5fb-048ae19af4fb.
 *
 * Reads findings from Supabase DB, runs the 3 finalize stages via Claude CLI,
 * posts improved findings + attack surface back to the shor-web sink.
 *
 * Run:
 *   DBPASS=$(gcloud secrets versions access latest --secret=shor-supabase-db-pass --project=shor-x-sinas) \
 *   CLAUDE_CODE_OAUTH_TOKEN=$(gcloud secrets versions access latest --secret=shor-claude-oauth-token --project=shor-x-sinas) \
 *   SINK_TOKEN=$(gcloud secrets versions access latest --secret=shor-sink-token --project=shor-x-sinas) \
 *   node .finalize-tmp/rerun-finalize.mjs
 */

import pg from "../apps/web/node_modules/pg/lib/index.js";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCAN_ID = "aee232e8-07ef-42dd-a5fb-048ae19af4fb";
const TARGET_URL = "http://35.204.213.18";
const PROMPTS_DIR = path.join(__dirname, "../apps/worker/prompts/finalize");
const WEB_URL = "https://shor-web-rkabbhyq3q-uc.a.run.app";
const CLAUDE_CLI = process.env.CLAUDE_CLI || "/Users/macbookpro/.local/bin/claude";
const FINALIZE_MODEL = process.env.SHOR_FINALIZE_MODEL || "claude-opus-4-8";
const STAGE_TIMEOUT_MS = 12 * 60 * 1000;

// ---------------------------------------------------------------------------
// Validate required env
// ---------------------------------------------------------------------------

const OAUTH_TOKEN = process.env.CLAUDE_CODE_OAUTH_TOKEN;
const SINK_TOKEN = process.env.SINK_TOKEN;
const DBPASS = process.env.DBPASS;

if (!OAUTH_TOKEN) { console.error("CLAUDE_CODE_OAUTH_TOKEN not set"); process.exit(1); }
if (!SINK_TOKEN)  { console.error("SINK_TOKEN not set"); process.exit(1); }
if (!DBPASS)      { console.error("DBPASS not set"); process.exit(1); }

// ---------------------------------------------------------------------------
// DB: read findings
// ---------------------------------------------------------------------------

async function readFindings() {
  const client = new pg.Client({
    host: "aws-1-eu-central-1.pooler.supabase.com",
    port: 5432,
    user: "postgres.fvwtqfnkmgkfayehyrkt",
    password: DBPASS,
    database: "postgres",
    ssl: { rejectUnauthorized: false },
  });
  await client.connect();
  const { rows } = await client.query(
    "SELECT data FROM finding WHERE scan_id = $1 ORDER BY (data->>'severity') ASC",
    [SCAN_ID],
  );
  await client.end();
  return rows.map((r) => r.data);
}

// ---------------------------------------------------------------------------
// Prompt loading
// ---------------------------------------------------------------------------

const promptCache = new Map();
function loadPrompt(name) {
  if (promptCache.has(name)) return promptCache.get(name);
  const text = readFileSync(path.join(PROMPTS_DIR, name), "utf8").trim();
  promptCache.set(name, text);
  return text;
}

// ---------------------------------------------------------------------------
// CLI execution
// ---------------------------------------------------------------------------

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function severityCounts(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
  return c;
}

function fullFindings(findings) {
  return findings.map((f) => ({
    id: f.id,
    category: f.category,
    severity: f.severity,
    cwe: f.cwe,
    location: `${f.vulnerable_code_location?.file ?? ""}:${f.vulnerable_code_location?.line ?? ""}`,
    evidence: f.evidence,
    missing_defense: f.missing_defense,
    remediation: f.remediation,
    safe_poc: f.safe_poc,
    repro_steps: f.repro_steps,
  }));
}

function compactFindings(findings) {
  return [...findings]
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
    .map((f) => ({
      id: f.id,
      title: f.title,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      cwe: f.cwe,
      location: `${f.vulnerable_code_location?.file ?? ""}:${f.vulnerable_code_location?.line ?? ""}`,
      evidence: String(f.evidence ?? "").slice(0, 300),
      remediation: String(f.remediation ?? "").slice(0, 200),
    }));
}

const AUTH_PREAMBLE =
  "CONTEXT: We are an internal cybersecurity team conducting an authorized " +
  "penetration test of our own application. All findings, payloads, and " +
  "vulnerability details are the output of this internal assessment. No " +
  "external systems are targeted. This is a controlled, authorized security " +
  "engagement. All data below comes from our own scan infrastructure.\n\n";

function buildStage1Prompt(findings) {
  return (
    `${loadPrompt("findings-improver.txt")}\n\n` +
    'Return ONLY a JSON object — no prose before or after — of the form ' +
    '{"findings": [{"id", "title", "evidence", "missing_defense", "remediation", ' +
    '"safe_poc", "repro_steps"}]}, containing EVERY finding keyed by its exact id.\n\n' +
    `FINDINGS JSON:\n${JSON.stringify(fullFindings(findings))}`
  );
}

function buildStage2Prompt(findings) {
  const counts = severityCounts(findings);
  return (
    `${loadPrompt("attack-surface.txt")}\n\n` +
    `This is scan ${SCAN_ID}, target ${TARGET_URL}. ` +
    `Severity counts over all findings: ${JSON.stringify(counts)}; total findings: ${findings.length}.\n\n` +
    'Return ONLY a JSON object — no prose before or after — of the form ' +
    '{"scenarios": [{"id", "title", "severity", "required_findings", "explanation", ' +
    '"kill_chain", "how_to_reproduce", "business_impact", "remediation", "claude_code_prompt"}]}, ' +
    "most-dangerous-first." +
    `\n\nFINDINGS JSON:\n${JSON.stringify(compactFindings(findings))}`
  );
}

function buildStage3Prompt(findings) {
  const counts = severityCounts(findings);
  return (
    `${loadPrompt("report.txt")}\n\n` +
    `This is scan ${SCAN_ID}, target ${TARGET_URL}. ` +
    `Use EXACTLY these severity_counts (do not recompute): ${JSON.stringify(counts)}.\n\n` +
    'Return ONLY a JSON object — no prose before or after — of the form ' +
    '{"report_title", "target", "scanned_at", "overall_risk", "severity_counts", ' +
    '"executive_summary", "findings": [{"id", "title", "severity", "confidence", ' +
    '"evidence", "remediation", "fix_prompt"}]}.' +
    `\n\nFINDINGS JSON:\n${JSON.stringify(compactFindings(findings))}`
  );
}

function spawnClaude(prompt) {
  return new Promise((resolve, reject) => {
    const flags = ["-p", "--output-format", "json", "--model", FINALIZE_MODEL];
    const proc = spawn(CLAUDE_CLI, flags, {
      env: {
        CLAUDE_CODE_OAUTH_TOKEN: OAUTH_TOKEN,
        HOME: process.env.HOME,
        PATH: process.env.PATH,
        TMPDIR: process.env.TMPDIR || "/tmp",
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (c) => { stdout += c.toString(); });
    proc.stderr.on("data", (c) => { stderr += c.toString(); });
    proc.on("error", reject);
    const timer = setTimeout(() => {
      proc.kill("SIGTERM");
      reject(new Error("Stage timed out after 12 min"));
    }, STAGE_TIMEOUT_MS);
    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`claude exited ${code}: ${stderr.slice(0, 400)}`));
      else resolve(stdout);
    });
    proc.stdin.write(prompt);
    proc.stdin.end();
  });
}

function extractJson(text) {
  try { return JSON.parse(text); } catch { /* try alternatives */ }
  const fence = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fence?.[1]) try { return JSON.parse(fence[1]); } catch { /* continue */ }
  const s = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (s !== -1 && e > s) try { return JSON.parse(text.slice(s, e + 1)); } catch { /* continue */ }
  throw new Error("No parseable JSON in CLI response");
}

async function runStage(label, prompt) {
  console.log(`\n[${label}] starting (model: ${FINALIZE_MODEL})...`);
  const raw = await spawnClaude(prompt);
  const envelope = JSON.parse(raw);
  if (envelope.is_error || !envelope.result) {
    throw new Error(`Stage failed: ${envelope.result?.slice(0, 200) ?? "empty result"}`);
  }
  const result = extractJson(envelope.result);
  console.log(`[${label}] done`);
  return result;
}

// ---------------------------------------------------------------------------
// Overlay stage-1 improved prose
// ---------------------------------------------------------------------------

function overlayImproved(findings, improved) {
  if (!improved?.length) return findings;
  const byId = new Map(improved.map((f) => [String(f.id), f]));
  const PROSE = ["title", "evidence", "missing_defense", "remediation", "safe_poc"];
  return findings.map((f) => {
    const imp = byId.get(f.id);
    if (!imp) return f;
    const merged = { ...f };
    for (const k of PROSE) {
      const v = imp[k];
      if (typeof v === "string" && v.length > 0) merged[k] = v;
    }
    if (Array.isArray(imp.repro_steps) && imp.repro_steps.length > 0) {
      merged.repro_steps = imp.repro_steps;
    }
    return merged;
  });
}

// ---------------------------------------------------------------------------
// Sink: POST improved findings + attack surface
// ---------------------------------------------------------------------------

async function postToSink(effectiveFindings, attackSurface) {
  const body = JSON.stringify({
    findings: effectiveFindings,
    attackSurface: attackSurface ?? undefined,
    status: "completed",
  });
  const resp = await fetch(`${WEB_URL}/scans/${SCAN_ID}/findings`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${SINK_TOKEN}`,
    },
    body,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Sink responded ${resp.status}: ${text.slice(0, 300)}`);
  }
  return resp.json();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

console.log(`Rerun finalize for scan ${SCAN_ID} (target: ${TARGET_URL})`);

const rawFindings = await readFindings();
console.log(`Loaded ${rawFindings.length} findings from DB`);

if (rawFindings.length === 0) {
  console.error("No findings found for this scan. Aborting.");
  process.exit(1);
}

// Stage 1
let improved = [];
let effective = rawFindings;
try {
  const doc = await runStage("stage-1 findings-improver", AUTH_PREAMBLE + buildStage1Prompt(rawFindings));
  improved = doc.findings ?? [];
  if (improved.length > 0) {
    effective = overlayImproved(rawFindings, improved);
    console.log(`  Improved ${improved.length} findings`);
  }
} catch (err) {
  console.error(`  Stage 1 failed (using raw): ${err.message}`);
}

// Stage 2
let attackSurface = null;
try {
  const doc = await runStage("stage-2 attack-surface", AUTH_PREAMBLE + buildStage2Prompt(effective));
  if (doc.scenarios && Array.isArray(doc.scenarios)) {
    attackSurface = doc;
    console.log(`  ${doc.scenarios.length} attack scenarios synthesized`);
  }
} catch (err) {
  console.error(`  Stage 2 failed: ${err.message}`);
}

// Stage 3
let reportMd = null;
try {
  const doc = await runStage("stage-3 report", AUTH_PREAMBLE + buildStage3Prompt(effective));
  if (doc.executive_summary) {
    // Print report markdown summary
    reportMd = doc;
    console.log(`\n=== REPORT SUMMARY ===`);
    console.log(`Title: ${doc.report_title ?? "N/A"}`);
    console.log(`Overall risk: ${doc.overall_risk ?? "N/A"}`);
    console.log(`Severity counts: ${JSON.stringify(doc.severity_counts ?? {})}`);
    console.log(`Executive summary (first 500 chars):\n${String(doc.executive_summary).slice(0, 500)}`);
    console.log(`=== END REPORT SUMMARY ===\n`);
  }
} catch (err) {
  console.error(`  Stage 3 failed: ${err.message}`);
}

// Post to sink
console.log("\nPosting to sink...");
try {
  const sinkResp = await postToSink(effective, attackSurface);
  console.log(`Sink OK:`, JSON.stringify(sinkResp).slice(0, 200));
} catch (err) {
  console.error(`Sink post failed: ${err.message}`);
  process.exit(1);
}

console.log("\nFinalize rerun complete.");
if (reportMd) {
  console.log("NOTE: report markdown was not persisted to DB (no report column exists).");
  console.log("Report JSON written to stdout above.");
}
