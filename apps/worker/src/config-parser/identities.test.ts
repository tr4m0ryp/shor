// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import { distributeConfig } from "./distribute.js";
import { parseConfigYAML } from "./parse.js";
import { sanitizeIdentity } from "./sanitize.js";

const MULTI = `
authentication:
  login_type: form
  login_url: https://target.example/login
  credentials:
    username: primary-user
    password: primary-pass
  success_condition:
    type: url_contains
    value: /dashboard
  identities:
    - label: Tenant Admin
      role: Owner
      credentials:
        username: admin-user
        password: admin-pass
        totp_secret: JBSWY3DPEHPK3PXP
    - label: member
      credentials:
        username: member-user
        password: member-pass
`;

describe("authentication.identities[] parsing", () => {
	it("parses secondary identities (label/role/credentials) into the Config", () => {
		const config = parseConfigYAML(MULTI);
		const ids = config.authentication?.identities;
		expect(ids).toHaveLength(2);
		expect(ids?.[0]?.label).toBe("Tenant Admin");
		expect(ids?.[0]?.role).toBe("Owner");
		expect(ids?.[0]?.credentials.username).toBe("admin-user");
		expect(ids?.[0]?.credentials.totp_secret).toBe("JBSWY3DPEHPK3PXP");
		// role is optional — the second identity omits it
		expect(ids?.[1]?.label).toBe("member");
		expect(ids?.[1]?.role).toBeUndefined();
	});

	it("threads identities through distributeConfig (not silently dropped)", () => {
		const distributed = distributeConfig(parseConfigYAML(MULTI));
		expect(distributed.authentication?.identities).toHaveLength(2);
	});
});

describe("identity sanitization", () => {
	it("trims label/role/username but preserves the password body verbatim", () => {
		const cleaned = sanitizeIdentity({
			label: "  Tenant Admin  ",
			role: "  Owner  ",
			credentials: {
				username: "  admin-user  ",
				password: "  keep me as-is  ",
				totp_secret: "  JBSWY3DPEHPK3PXP  ",
			},
			success_condition: { type: "url_contains", value: "  /admin  " },
		});
		expect(cleaned.label).toBe("Tenant Admin");
		expect(cleaned.role).toBe("Owner");
		expect(cleaned.credentials.username).toBe("admin-user");
		expect(cleaned.credentials.password).toBe("  keep me as-is  ");
		expect(cleaned.credentials.totp_secret).toBe("JBSWY3DPEHPK3PXP");
		expect(cleaned.success_condition?.value).toBe("/admin");
	});

	it("drops an absent role rather than emitting undefined", () => {
		const cleaned = sanitizeIdentity({
			label: "member",
			credentials: { username: "m", password: "p" },
		});
		expect("role" in cleaned).toBe(false);
		expect("success_condition" in cleaned).toBe(false);
	});
});

describe("identity security gate (dangerous-pattern parity with primary auth)", () => {
	it("rejects a label that trips the dangerous-pattern gate", () => {
		const bad = MULTI.replace("label: member", 'label: "<script>"');
		expect(() => parseConfigYAML(bad)).toThrow(/dangerous pattern/i);
	});

	it("rejects an identity credential that trips the gate (path traversal)", () => {
		const bad = MULTI.replace("password: member-pass", "password: ../../etc/passwd");
		expect(() => parseConfigYAML(bad)).toThrow(/dangerous pattern/i);
	});

	it("rejects a role carrying a javascript: scheme", () => {
		const bad = MULTI.replace("role: Owner", "role: javascript:alert(1)");
		expect(() => parseConfigYAML(bad)).toThrow(/dangerous pattern/i);
	});
});
