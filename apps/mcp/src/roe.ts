/**
 * RoE (Rules of Engagement) schema — the connector-side mirror of the engine's
 * `guardrails/roe.ts` contract. Declared as Zod so the signed allowlist a routine
 * passes to `start_blackbox_run` is shape-validated at the tool boundary before it
 * ever reaches the engine. The engine re-validates and, crucially, RE-ENFORCES it
 * (default-deny): if the two ever disagreed, the engine's copy wins and the run
 * reaches nothing — the safe failure.
 */

import { z } from 'zod';

export const roeSchemeSchema = z.enum(['http', 'https']);

export const roeHostRuleSchema = z.object({
  host: z.string().min(1).describe('Lowercase hostname, no scheme/port/path (e.g. app.example.com).'),
  includeSubdomains: z.boolean().optional().describe('When true, *.host subdomains are also in scope.'),
  schemes: z.array(roeSchemeSchema).optional().describe('Allowed schemes; empty ⇒ https only.'),
  pathPrefixes: z.array(z.string()).optional().describe('Allowed path prefixes (/api, /); empty ⇒ whole host.'),
  ports: z.array(z.number().int().min(1).max(65535)).optional().describe('Allowed ports; empty ⇒ scheme default.'),
});

export const roeSchema = z.object({
  version: z.literal(1),
  targetUrl: z.string().url().describe('The scan target this RoE governs.'),
  allowedHosts: z
    .array(roeHostRuleSchema)
    .min(1)
    .describe('The DEFAULT-DENY host allowlist. An empty list authorizes nothing.'),
  deniedHosts: z.array(z.string()).optional().describe('Hard deny-list applied after the allowlist.'),
});

export type Roe = z.infer<typeof roeSchema>;
