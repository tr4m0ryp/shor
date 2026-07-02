// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

export class Timer {
	name: string;
	startTime: number;
	endTime: number | null = null;

	constructor(name: string) {
		this.name = name;
		this.startTime = Date.now();
	}

	stop(): number {
		this.endTime = Date.now();
		return this.duration();
	}

	duration(): number {
		const end = this.endTime || Date.now();
		return end - this.startTime;
	}
}
