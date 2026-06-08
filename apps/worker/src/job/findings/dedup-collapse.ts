// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic finding de-duplication + collapse (T6 / B1-B2).
 *
 * Scan output re-reports one root cause under many category labels (e.g. the same
 * SSRF sink 5×, the same hardcoded key ~6×). This module groups records that share
 * a location+CWE (the `partialFingerprints["locationCwe/v1"]` key, else file:line,
 * else the full fingerprint) and COLLAPSES each group to one canonical record. The
 * other members are folded into the representative's `also_reported_as` — PRESERVED,
 * never deleted; the report simply shows the cluster once.
 *
 * No LLM, no IO — pure and synchronous. Records the optional LLM root-cause judge
 * (`services/dedup-judge`) already clustered keep their `cluster_id`; this only fills
 * the gaps, so the two compose.
 */

import { createHash } from 'node:crypto';
import type { FindingRecord, FindingSeverity } from './types.js';

const SEV_RANK: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Deterministic grouping key: location+CWE partial fingerprint → file:line → full fingerprint. */
function groupKey(rec: FindingRecord): string {
  const partial = rec.partialFingerprints?.['locationCwe/v1'];
  if (typeof partial === 'string' && partial) return `p:${partial}`;
  const loc = rec.vulnerable_code_location;
  if (loc?.file) return `l:${loc.file.toLowerCase()}:${loc.line}`;
  return `f:${rec.fingerprint}`;
}

function clusterIdFor(key: string): string {
  return `cl_${createHash('sha1').update(key).digest('hex').slice(0, 12)}`;
}

/**
 * Assign a deterministic `cluster_id` to every record that lacks one (records the
 * LLM judge already clustered keep theirs). Same location+CWE (or file:line) ⇒ same
 * cluster. Pure; returns new record objects; never drops.
 */
export function clusterDeterministic(records: FindingRecord[]): FindingRecord[] {
  return records.map((r) => (r.cluster_id ? r : { ...r, cluster_id: clusterIdFor(groupKey(r)) }));
}

/** Prefer `a` over `b` as representative: higher severity, then confirmed, then richer evidence. */
function better(a: FindingRecord, b: FindingRecord): FindingRecord {
  const sa = SEV_RANK[a.severity] ?? 9;
  const sb = SEV_RANK[b.severity] ?? 9;
  if (sa !== sb) return sa < sb ? a : b;
  const ca = a.confidence === 'confirmed' ? 0 : 1;
  const cb = b.confidence === 'confirmed' ? 0 : 1;
  if (ca !== cb) return ca < cb ? a : b;
  return String(a.evidence ?? '').length >= String(b.evidence ?? '').length ? a : b;
}

/** Canonical representative of a non-empty member list (reduce ⇒ always defined). */
function pickRepresentative(members: FindingRecord[]): FindingRecord {
  return members.reduce((best, cur) => better(best, cur));
}

/**
 * Collapse clustered records to ONE canonical record per `cluster_id`. Other members'
 * titles+ids are folded into the representative's `also_reported_as` (PRESERVED — the
 * report shows the cluster once, nothing is lost). Singletons pass through unchanged.
 * Cluster output order follows first-seen input order.
 */
export function collapseClusters(records: FindingRecord[]): FindingRecord[] {
  const order: string[] = [];
  const byCluster = new Map<string, FindingRecord[]>();
  for (const r of records) {
    const key = r.cluster_id ?? r.id;
    let bucket = byCluster.get(key);
    if (!bucket) {
      bucket = [];
      byCluster.set(key, bucket);
      order.push(key);
    }
    bucket.push(r);
  }

  const out: FindingRecord[] = [];
  for (const key of order) {
    const members = byCluster.get(key) ?? [];
    const [single] = members;
    if (members.length === 1 && single) {
      out.push(single);
      continue;
    }
    const rep = pickRepresentative(members);
    const existing = Array.isArray(rep.also_reported_as) ? rep.also_reported_as : [];
    const folded = members.filter((m) => m !== rep).map((m) => `${m.title} (${m.id})`);
    out.push({ ...rep, also_reported_as: [...existing, ...folded] });
  }
  return out;
}

/** Deterministic cluster + collapse in one call. */
export function dedupAndCollapse(records: FindingRecord[]): FindingRecord[] {
  return collapseClusters(clusterDeterministic(records));
}
