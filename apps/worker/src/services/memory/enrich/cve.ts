// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Known-vuln ENRICHMENT (spec T6, R10): OSV.dev batch -> GHSA -> NVD.
 *
 * A finding that names a dependency `component@version` is checked against
 * OSV.dev's free `POST /v1/querybatch` (SCA). A hit labels the finding KNOWN and
 * attaches the advisory ids; an optional hydrator pulls GHSA/NVD detail (CWE,
 * summary, severity) — mirrored so a batch stays cheap. A finding with no OSV
 * match is NOVEL: we carry the tool's `rule_id -> CWE` as an ADVISORY CWE
 * (flagged, not authoritative) rather than inventing a match.
 *
 * The OSV/advisory transports and the CVE registry are injected PORTS, so the
 * pure labeling logic is unit-tested with fakes (spec stop-condition: implement
 * against the documented API, mock in tests).
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { extractMetadata } from "../schema/index.js";
import type { FindingLike } from "../schema/index.js";

/** OSV.dev batch endpoint (documented free API). */
export const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
/** OSV querybatch accepts up to ~1000 queries per call. */
const MAX_BATCH = 1000;

/** A dependency reference resolved from a finding. */
export interface ComponentRef {
	readonly name: string;
	readonly ecosystem: string;
	readonly version?: string | null;
}

/** OSV querybatch request query (documented shape). */
export interface OsvQuery {
	readonly package: { readonly name: string; readonly ecosystem: string };
	readonly version?: string;
}

/** One OSV vuln reference (querybatch returns id + modified only). */
export interface OsvVulnRef {
	readonly id: string;
	readonly modified?: string;
}

/** OSV querybatch response (results align 1:1 with the queries). */
export interface OsvBatchResponse {
	readonly results: ReadonlyArray<{ readonly vulns?: readonly OsvVulnRef[] }>;
}

/** Injected OSV transport (default client below; tests pass a fake). */
export interface OsvClient {
	queryBatch(queries: readonly OsvQuery[]): Promise<OsvBatchResponse>;
}

/** Minimal `fetch`-shaped transport (avoids depending on a global `fetch` type). */
export interface HttpPostJson {
	(
		url: string,
		init: { method: string; headers: Record<string, string>; body: string },
	): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;
}

/** Hydrated GHSA/NVD advisory detail for one id. */
export interface AdvisoryDetail {
	readonly id: string;
	readonly cwe?: string | null;
	readonly summary?: string | null;
	readonly severity?: string | null;
}

/** Optional GHSA/NVD hydrator (mirrored advisory lookup by id). */
export type AdvisoryHydrator = (id: string) => Promise<AdvisoryDetail | null>;

/** Optional CVE-registry upsert port (apps/web `cveRegistryRepo.upsert`). */
export interface CveRegistryWriter {
	upsert(input: {
		cveId: string;
		package?: string | null;
		cwe?: string | null;
	}): Promise<{ id: string }>;
}

/** Per-finding enrichment outcome (known vs novel). */
export interface CveEnrichment {
	readonly findingId: string;
	/** `known` when OSV matched a dependency; else `novel`. */
	readonly novelty: "known" | "novel";
	readonly component?: ComponentRef;
	readonly cveIds: readonly string[];
	readonly advisories: readonly AdvisoryDetail[];
	/** For novel bugs: the tool `rule_id -> CWE` carried as advisory-only. */
	readonly autoCwe?: string;
	readonly autoCweAdvisory?: boolean;
}

/** True when `SHOR_CVE_ENRICH` is truthy. */
export function readCveEnrichEnabled(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	const raw = env["SHOR_CVE_ENRICH"]?.trim().toLowerCase();
	return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

function firstString(finding: FindingLike, keys: readonly string[]): string | null {
	for (const key of keys) {
		const v = finding[key];
		if (typeof v === "string" && v.trim() !== "") return v.trim();
	}
	return null;
}

/**
 * Resolve a `component@version` (+ ecosystem) from a finding, or null when it
 * names no dependency (a pure code finding). Ecosystem comes from an explicit
 * field or the injected default; without one the component is not OSV-queryable.
 */
export function componentOf(
	finding: FindingLike,
	defaultEcosystem?: string,
): ComponentRef | null {
	const meta = extractMetadata(finding);
	const combined = meta.componentVer;
	if (!combined) return null;
	const at = combined.lastIndexOf("@");
	const name = at > 0 ? combined.slice(0, at) : combined;
	const version = at > 0 ? combined.slice(at + 1) : null;
	const ecosystem =
		firstString(finding, ["ecosystem", "package_ecosystem", "registry"]) ??
		defaultEcosystem ??
		null;
	if (!ecosystem) return null;
	return { name, ecosystem, ...(version ? { version } : {}) };
}

/** Build the OSV query for a component (omits version when unknown). */
function toQuery(c: ComponentRef): OsvQuery {
	return {
		package: { name: c.name, ecosystem: c.ecosystem },
		...(c.version ? { version: c.version } : {}),
	};
}

/** Default OSV client over an injected/global `fetch` (POST querybatch). */
export function createOsvClient(opts: {
	fetchImpl?: HttpPostJson;
	url?: string;
} = {}): OsvClient {
	const url = opts.url ?? OSV_BATCH_URL;
	const doFetch =
		opts.fetchImpl ?? (globalThis as { fetch?: HttpPostJson }).fetch;
	return {
		async queryBatch(queries) {
			if (!doFetch) throw new Error("no fetch implementation available");
			const res = await doFetch(url, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ queries }),
			});
			if (!res.ok) throw new Error(`OSV querybatch failed: HTTP ${res.status}`);
			return (await res.json()) as OsvBatchResponse;
		},
	};
}

/** Injected collaborators for {@link enrichFindings}. */
export interface EnrichDeps {
	readonly osv: OsvClient;
	readonly hydrate?: AdvisoryHydrator;
	readonly registry?: CveRegistryWriter;
	/** Fallback ecosystem when a finding omits one. */
	readonly defaultEcosystem?: string;
	/** Tool `rule_id -> CWE` map for advisory-CWE on novel bugs. */
	readonly ruleCweMap?: Readonly<Record<string, string>>;
	readonly logger?: ActivityLogger | undefined;
	/** Override the `SHOR_CVE_ENRICH` env gate (mainly for tests). */
	readonly enabled?: boolean | undefined;
}

/** Advisory CWE for a novel finding: explicit CWE, else the rule_id map. */
function advisoryCwe(
	finding: FindingLike,
	ruleCweMap: Readonly<Record<string, string>>,
): string | undefined {
	const ruleId = firstString(finding, ["rule_id", "ruleId", "check_id"]);
	if (ruleId && ruleCweMap[ruleId]) return ruleCweMap[ruleId];
	const cwe = firstString(finding, ["cwe"]);
	return cwe ?? undefined;
}

/**
 * Enrich a finding set against OSV.dev. Batches all component queries into one
 * (chunked) OSV call, optionally hydrates GHSA/NVD detail, labels each finding
 * `known` (OSV hit) or `novel` (advisory CWE carried), and optionally caches
 * hits in the CVE registry. Disabled (`SHOR_CVE_ENRICH` off) -> every finding
 * `novel`, no network. Never throws: an OSV failure degrades all to `novel`.
 */
export async function enrichFindings(
	findings: readonly FindingLike[],
	deps: EnrichDeps,
): Promise<CveEnrichment[]> {
	const enabled = deps.enabled ?? readCveEnrichEnabled();
	const ruleCweMap = deps.ruleCweMap ?? {};
	const components = findings.map((f) => componentOf(f, deps.defaultEcosystem));

	if (!enabled)
		return findings.map((f, i) => novelResult(f, components[i] ?? undefined, ruleCweMap));

	// One de-duplicated batch query over all resolvable components.
	const queryKeys = new Map<string, OsvQuery>();
	for (const c of components) {
		if (c) queryKeys.set(`${c.ecosystem}|${c.name}|${c.version ?? ""}`, toQuery(c));
	}
	const byKey = await runBatch([...queryKeys], deps);

	const out: CveEnrichment[] = [];
	for (let i = 0; i < findings.length; i++) {
		const finding = findings[i]!;
		const c = components[i];
		const vulns = c
			? byKey.get(`${c.ecosystem}|${c.name}|${c.version ?? ""}`)
			: undefined;
		if (!c || !vulns || vulns.length === 0) {
			out.push(novelResult(finding, c ?? undefined, ruleCweMap));
			continue;
		}
		const advisories = await hydrateAll(vulns, deps);
		out.push({
			findingId: idOf(finding),
			novelty: "known",
			component: c,
			cveIds: vulns.map((v) => v.id),
			advisories,
		});
		await cacheHits(c, advisories, vulns, deps);
	}
	deps.logger?.info?.("cve-enrich: complete", {
		findings: findings.length,
		known: out.filter((e) => e.novelty === "known").length,
	});
	return out;
}

/** Run the (chunked) OSV batch; returns query-key -> vulns. Fails to empty. */
async function runBatch(
	entries: ReadonlyArray<[string, OsvQuery]>,
	deps: EnrichDeps,
): Promise<Map<string, OsvVulnRef[]>> {
	const byKey = new Map<string, OsvVulnRef[]>();
	for (let start = 0; start < entries.length; start += MAX_BATCH) {
		const chunk = entries.slice(start, start + MAX_BATCH);
		try {
			const res = await deps.osv.queryBatch(chunk.map(([, q]) => q));
			res.results.forEach((r, idx) => {
				byKey.set(chunk[idx]![0], [...(r.vulns ?? [])]);
			});
		} catch (err) {
			deps.logger?.warn?.("cve-enrich: OSV batch failed (all -> novel)", {
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return byKey;
}

/** Hydrate GHSA/NVD detail for each id (best-effort; skips on failure). */
async function hydrateAll(
	vulns: readonly OsvVulnRef[],
	deps: EnrichDeps,
): Promise<AdvisoryDetail[]> {
	if (!deps.hydrate) return [];
	const out: AdvisoryDetail[] = [];
	for (const v of vulns) {
		try {
			const d = await deps.hydrate(v.id);
			if (d) out.push(d);
		} catch (err) {
			deps.logger?.warn?.("cve-enrich: advisory hydrate failed", {
				id: v.id,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return out;
}

/** Cache known-vuln hits in the CVE registry (best-effort). */
async function cacheHits(
	c: ComponentRef,
	advisories: readonly AdvisoryDetail[],
	vulns: readonly OsvVulnRef[],
	deps: EnrichDeps,
): Promise<void> {
	if (!deps.registry) return;
	const cweById = new Map(advisories.map((a) => [a.id, a.cwe ?? null]));
	for (const v of vulns) {
		try {
			await deps.registry.upsert({
				cveId: v.id,
				package: c.name,
				cwe: cweById.get(v.id) ?? null,
			});
		} catch (err) {
			deps.logger?.warn?.("cve-enrich: registry upsert failed", {
				id: v.id,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
}

function novelResult(
	finding: FindingLike,
	component: ComponentRef | undefined,
	ruleCweMap: Readonly<Record<string, string>>,
): CveEnrichment {
	const autoCwe = advisoryCwe(finding, ruleCweMap);
	return {
		findingId: idOf(finding),
		novelty: "novel",
		...(component ? { component } : {}),
		cveIds: [],
		advisories: [],
		...(autoCwe ? { autoCwe, autoCweAdvisory: true } : {}),
	};
}

function idOf(finding: FindingLike): string {
	if (typeof finding.id === "string" && finding.id) return finding.id;
	if (typeof finding.fingerprint === "string" && finding.fingerprint)
		return finding.fingerprint;
	return "";
}
