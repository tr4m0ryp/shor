// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import { renderThreatModel } from "./render.js";
import { parseThreatModel, threatScore } from "./schema.js";

const SAMPLE = JSON.stringify({
	system_context: "Multi-tenant SaaS billing API behind a reverse proxy.",
	assets: [
		{
			asset: "customer PII",
			description: "names, emails, billing addresses",
			sensitivity: "critical",
		},
		{ asset: "marketing copy", description: "public site text", sensitivity: "low" },
	],
	entry_points: [
		{
			entry_point: "POST /api/login",
			trust_boundary: "internet -> app",
			reachable_assets: ["session tokens"],
		},
	],
	threats: [
		{
			id: "T1",
			threat: "low impact, rarely reachable",
			actor: "remote_unauth",
			surface: "GET /api/status",
			asset: "marketing copy",
			impact: "low",
			likelihood: "rare",
			status: "open",
			controls: "",
			evidence: "",
		},
		{
			id: "T2",
			threat: "cross-tenant IDOR exposes other tenants' invoices",
			actor: "remote_auth",
			surface: "GET /api/invoices/{id}",
			asset: "customer PII",
			impact: "critical",
			likelihood: "likely",
			status: "open",
			controls: "ownership check missing",
			evidence: "no tenant scoping at invoices.ts:88",
		},
	],
	deprioritized: [{ item: "self-XSS", reason: "needs victim to paste payload" }],
	provenance: { sources: ["recon_deliverable.md"], notes: "from recon" },
});

describe("parseThreatModel", () => {
	it("parses a well-formed model", () => {
		const model = parseThreatModel(SAMPLE);
		expect(model).not.toBeNull();
		expect(model?.threats).toHaveLength(2);
		expect(model?.assets[0]?.sensitivity).toBe("critical");
		expect(model?.provenance.sources).toContain("recon_deliverable.md");
	});

	it("returns null for a non-object or a model without a threats array", () => {
		expect(parseThreatModel("[]")).toBeNull();
		expect(parseThreatModel("not json at all")).toBeNull();
		expect(parseThreatModel(JSON.stringify({ assets: [] }))).toBeNull();
	});

	it("tolerates field drift: unknown enums fall to lowest rank, ids synthesized", () => {
		const model = parseThreatModel(
			JSON.stringify({
				threats: [{ threat: "x", impact: "apocalyptic", likelihood: "meh" }],
			}),
		);
		expect(model?.threats[0]?.impact).toBe("low");
		expect(model?.threats[0]?.likelihood).toBe("very_rare");
		expect(model?.threats[0]?.id).toBe("T1");
	});
});

describe("renderThreatModel", () => {
	it("renders a non-empty summary, threats ranked by impact x likelihood", () => {
		const model = parseThreatModel(SAMPLE);
		expect(model).not.toBeNull();
		if (!model) return;
		const summary = renderThreatModel(model);
		expect(summary.length).toBeGreaterThan(0);
		expect(summary).toContain("Top threats");
		// T2 (critical x likely) outranks T1 (low x rare) -> listed first.
		const posT2 = summary.indexOf("T2");
		const posT1 = summary.indexOf("T1");
		expect(posT2).toBeGreaterThanOrEqual(0);
		expect(posT1).toBeGreaterThan(posT2);
		// crown-jewel asset + trust boundary surfaced.
		expect(summary).toContain("customer PII");
		expect(summary).toContain("internet -> app");
		// nothing left for the prompt interpolator to fill.
		expect(summary).not.toMatch(/\{\{.*\}\}/);
	});

	it("returns a non-empty string even for a model with no entries", () => {
		const model = parseThreatModel(JSON.stringify({ threats: [] }));
		expect(model).not.toBeNull();
		if (!model) return;
		expect(renderThreatModel(model).length).toBeGreaterThan(0);
	});
});

describe("threatScore", () => {
	it("scores higher impact x likelihood above lower", () => {
		const model = parseThreatModel(SAMPLE);
		if (!model) throw new Error("expected parse to succeed");
		const low = model.threats[0];
		const high = model.threats[1];
		if (!low || !high) throw new Error("expected two threats");
		expect(threatScore(high)).toBeGreaterThan(threatScore(low));
	});
});
