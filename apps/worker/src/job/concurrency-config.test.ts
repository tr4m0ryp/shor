// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { afterEach, describe, expect, it } from "vitest";
import { optionalBool, optionalPositiveInt } from "./env.js";
import { resolveGroupWidth } from "./pipeline.js";

describe("resolveGroupWidth", () => {
	it("unset config → full group width", () => {
		expect(resolveGroupWidth(undefined, 7)).toBe(7);
	});

	it("a configured value below the group size is honored", () => {
		expect(resolveGroupWidth(3, 7)).toBe(3);
	});

	it("clamps a configured value above the group size", () => {
		expect(resolveGroupWidth(20, 7)).toBe(7);
	});

	it("ignores zero / negative (falls back to full)", () => {
		expect(resolveGroupWidth(0, 7)).toBe(7);
		expect(resolveGroupWidth(-4, 7)).toBe(7);
	});
});

describe("optionalPositiveInt", () => {
	const KEY = "SHOR_TEST_GROUP_CONCURRENCY";
	afterEach(() => {
		delete process.env[KEY];
	});

	it("undefined when unset", () => {
		expect(optionalPositiveInt(KEY)).toBeUndefined();
	});

	it("parses a positive integer", () => {
		process.env[KEY] = "4";
		expect(optionalPositiveInt(KEY)).toBe(4);
	});

	it("rejects non-positive / non-integer / garbage", () => {
		for (const bad of ["0", "-2", "2.5", "abc", ""]) {
			process.env[KEY] = bad;
			expect(optionalPositiveInt(KEY)).toBeUndefined();
		}
	});
});

describe("optionalBool", () => {
	const KEY = "SHOR_TEST_EXPENDABLE_TARGET";
	afterEach(() => {
		delete process.env[KEY];
	});

	it("undefined when unset or empty (distinguishes unset from off)", () => {
		expect(optionalBool(KEY)).toBeUndefined();
		process.env[KEY] = "   ";
		expect(optionalBool(KEY)).toBeUndefined();
	});

	it("true for truthy spellings (1 / true / yes, case-insensitive)", () => {
		for (const v of ["1", "true", "TRUE", "yes", "Yes", " true "]) {
			process.env[KEY] = v;
			expect(optionalBool(KEY)).toBe(true);
		}
	});

	it("false for any other set value (off, not unset)", () => {
		for (const v of ["0", "false", "no", "off", "destroy"]) {
			process.env[KEY] = v;
			expect(optionalBool(KEY)).toBe(false);
		}
	});
});
