// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import {
	identitySessionLabel,
	identitySlug,
	PLAYWRIGHT_SESSION_MAPPING,
} from "./playwright-sessions.js";

describe("identitySlug", () => {
	it("lowercases and hyphenates whitespace", () => {
		expect(identitySlug("Tenant Admin")).toBe("tenant-admin");
	});

	it("collapses punctuation runs and trims edge hyphens", () => {
		expect(identitySlug("  Owner@Corp!! ")).toBe("owner-corp");
	});

	it("falls back to a stable token for degenerate input", () => {
		expect(identitySlug("")).toBe("identity");
		expect(identitySlug("***")).toBe("identity");
	});
});

describe("identitySessionLabel", () => {
	it("namespaces the label under identity-", () => {
		expect(identitySessionLabel("Member")).toBe("identity-member");
	});

	it("stays disjoint from the agent1..5 phase sessions", () => {
		const phaseSessions = new Set(Object.values(PLAYWRIGHT_SESSION_MAPPING));
		for (const label of ["primary", "tenant-admin", "agent1", "agent5"]) {
			expect(phaseSessions.has(identitySessionLabel(label) as never)).toBe(false);
		}
	});
});
