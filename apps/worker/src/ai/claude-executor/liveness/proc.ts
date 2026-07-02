// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Linux `/proc` sampling for the liveness watchdog. Every function degrades
 * safely when `/proc` is absent (non-Linux dev) — it returns null/empty, and the
 * monitor then disables itself rather than guess.
 *
 * Process-tree scoping is by an injected env TOKEN, not by PID parentage: under
 * the 7-wide vuln group every agent's SDK subprocess is a child of the SAME
 * worker PID, so PID alone can't tell them apart. Each agent tags its SDK env
 * with a unique token; the token's process set IS that agent's tree (the token
 * is inherited by every tool the agent spawns), regardless of fork depth.
 */

import { readFileSync, readdirSync } from "node:fs";
import type { ActivityLogger } from "../../../types/activity-logger.js";

/** Parsed essentials from `/proc/<pid>/stat`. */
interface StatInfo {
	ppid: number;
	cpuTicks: number;
}

/** Aggregate footprint of a process tree plus the leaf pids (the actual tools). */
export interface TreeSample {
	members: number[];
	cpuTicks: number;
	ioBytes: number;
	/** Tree leaves excluding the roots — the running tool processes to nudge first. */
	leaves: number[];
}

/** All numeric pids under `/proc`, or null when `/proc` is unavailable. */
function listPids(): number[] | null {
	try {
		return readdirSync("/proc")
			.filter((n) => /^\d+$/.test(n))
			.map(Number);
	} catch {
		return null; // not Linux / no procfs
	}
}

/** True when this host exposes `/proc` (so the watchdog can run at all). */
export function procAvailable(): boolean {
	return listPids() !== null;
}

/**
 * Parse `/proc/<pid>/stat`. The `comm` field is parenthesised and may contain
 * spaces/parens, so we split AFTER the last ')': the remaining tokens start at
 * field 3 (state), making ppid index 1, utime index 11, stime index 12.
 */
function readStat(pid: number): StatInfo | null {
	try {
		const raw = readFileSync(`/proc/${pid}/stat`, "utf8");
		const rparen = raw.lastIndexOf(")");
		if (rparen < 0) return null;
		const rest = raw.slice(rparen + 2).trim().split(/\s+/);
		const ppid = Number(rest[1]);
		const utime = Number(rest[11]);
		const stime = Number(rest[12]);
		if (!Number.isFinite(ppid)) return null;
		return {
			ppid,
			cpuTicks:
				(Number.isFinite(utime) ? utime : 0) +
				(Number.isFinite(stime) ? stime : 0),
		};
	} catch {
		return null;
	}
}

/** Sum `rchar`+`wchar` from `/proc/<pid>/io` — bytes via any syscall (disk OR socket). */
function readIoBytes(pid: number): number {
	try {
		const raw = readFileSync(`/proc/${pid}/io`, "utf8");
		let total = 0;
		for (const line of raw.split("\n")) {
			const m = /^(?:rchar|wchar):\s*(\d+)/.exec(line);
			if (m?.[1] !== undefined) total += Number(m[1]);
		}
		return total;
	} catch {
		return 0; // io may be restricted; treat as no contribution
	}
}

/** True when `/proc/<pid>/environ` carries `token`. */
function environHasToken(pid: number, token: string): boolean {
	try {
		return readFileSync(`/proc/${pid}/environ`, "utf8").includes(token);
	} catch {
		return false; // not ours, or already gone
	}
}

/**
 * The root pids of the agent tree tagged with `token`: token-holders whose parent
 * is NOT itself a token-holder. Robust to any fork depth and to other concurrent
 * agents (each carries a different token). Empty until the SDK subprocess is up.
 */
export function findAgentRoots(token: string): number[] {
	const pids = listPids();
	if (pids === null) return [];
	const holders = new Set<number>();
	const ppidOf = new Map<number, number>();
	for (const pid of pids) {
		const stat = readStat(pid);
		if (!stat) continue;
		ppidOf.set(pid, stat.ppid);
		if (environHasToken(pid, token)) holders.add(pid);
	}
	const roots: number[] = [];
	for (const pid of holders) {
		const ppid = ppidOf.get(pid);
		if (ppid === undefined || !holders.has(ppid)) roots.push(pid);
	}
	return roots;
}

/**
 * Walk the descendant tree of `rootPids`, summing CPU + I/O and collecting the
 * leaf processes (no in-tree children, and not a root) — the actual tools to
 * SIGTERM first. Empty when `/proc` is gone or the tree has exited.
 */
export function walkTree(rootPids: readonly number[]): TreeSample {
	const empty: TreeSample = { members: [], cpuTicks: 0, ioBytes: 0, leaves: [] };
	const pids = listPids();
	if (pids === null || rootPids.length === 0) return empty;

	const statOf = new Map<number, StatInfo>();
	const childrenOf = new Map<number, number[]>();
	for (const pid of pids) {
		const stat = readStat(pid);
		if (!stat) continue;
		statOf.set(pid, stat);
		const kids = childrenOf.get(stat.ppid);
		if (kids) kids.push(pid);
		else childrenOf.set(stat.ppid, [pid]);
	}

	const members: number[] = [];
	const seen = new Set<number>();
	const queue = [...rootPids];
	while (queue.length > 0) {
		const pid = queue.shift() as number;
		if (seen.has(pid)) continue;
		seen.add(pid);
		members.push(pid);
		for (const c of childrenOf.get(pid) ?? []) queue.push(c);
	}

	const rootSet = new Set(rootPids);
	let cpuTicks = 0;
	let ioBytes = 0;
	const leaves: number[] = [];
	for (const pid of members) {
		cpuTicks += statOf.get(pid)?.cpuTicks ?? 0;
		ioBytes += readIoBytes(pid);
		const inTreeKids = (childrenOf.get(pid) ?? []).filter((c) => seen.has(c));
		if (inTreeKids.length === 0 && !rootSet.has(pid)) leaves.push(pid);
	}
	return { members, cpuTicks, ioBytes, leaves };
}

/** Send `signal` to each pid, swallowing ESRCH (already gone). Logs the count. */
export function signalPids(
	pids: readonly number[],
	signal: NodeJS.Signals,
	logger: ActivityLogger,
): void {
	let sent = 0;
	for (const pid of pids) {
		try {
			process.kill(pid, signal);
			sent += 1;
		} catch {
			// process already exited — nothing to do
		}
	}
	if (sent > 0) {
		logger.warn(`liveness-watchdog: sent ${signal} to ${sent} wedged process(es)`);
	}
}
