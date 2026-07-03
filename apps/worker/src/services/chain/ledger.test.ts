// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { PrimitiveLedger } from "./ledger.js";
import type { Primitive } from "./types.js";

function prim(over: Partial<Primitive> & Pick<Primitive, "id">): Primitive {
	return {
		privilege: "low_priv",
		sideEffect: "state_write",
		vulnClass: "stored_xss",
		summary: "test primitive",
		...over,
	};
}

describe("PrimitiveLedger", () => {
	it("is immutable: add returns a NEW ledger and leaves the original unchanged", () => {
		const a = PrimitiveLedger.create([prim({ id: "p1" })]);
		const b = a.add(prim({ id: "p2" }));
		expect(a.size).toBe(1);
		expect(b.size).toBe(2);
		expect(a).not.toBe(b);
	});

	it("freezes the backing array (cannot be mutated in place)", () => {
		const a = PrimitiveLedger.create([prim({ id: "p1" })]);
		expect(Object.isFrozen(a.all())).toBe(true);
		expect(() => (a.all() as Primitive[]).push(prim({ id: "x" }))).toThrow();
	});

	it("de-duplicates by id", () => {
		const a = PrimitiveLedger.create([prim({ id: "p1" }), prim({ id: "p1", summary: "dup" })]);
		expect(a.size).toBe(1);
	});

	it("indexes by privilege × side-effect bucket", () => {
		const ledger = PrimitiveLedger.create([
			prim({ id: "w", privilege: "low_priv", sideEffect: "state_write" }),
			prim({ id: "r", privilege: "high_priv", sideEffect: "render" }),
			prim({ id: "w2", privilege: "low_priv", sideEffect: "state_write" }),
		]);
		expect(ledger.by("low_priv", "state_write").map((p) => p.id).sort()).toEqual(["w", "w2"]);
		expect(ledger.by("high_priv", "render").map((p) => p.id)).toEqual(["r"]);
		expect(ledger.by("admin", "exec")).toEqual([]);
	});

	it("queries by privilege, side-effect, id, and predicate", () => {
		const ledger = PrimitiveLedger.create([
			prim({ id: "a", privilege: "unauth", sideEffect: "state_write" }),
			prim({ id: "b", privilege: "admin", sideEffect: "render" }),
		]);
		expect(ledger.byPrivilege("unauth").map((p) => p.id)).toEqual(["a"]);
		expect(ledger.bySideEffect("render").map((p) => p.id)).toEqual(["b"]);
		expect(ledger.get("b")?.privilege).toBe("admin");
		expect(ledger.find((p) => p.privilege === "admin").map((p) => p.id)).toEqual(["b"]);
	});

	it("addAll is a no-op for an empty list (returns the same instance)", () => {
		const a = PrimitiveLedger.create([prim({ id: "p1" })]);
		expect(a.addAll([])).toBe(a);
	});
});
