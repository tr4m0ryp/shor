// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

const SPINNER_BLUE = "\x1b[38;2;60;140;255m";
const RESET = "\x1b[0m";
const SUCCESS_GREEN = "\x1b[38;2;72;187;120m";

export class ProgressIndicator {
	private message: string;
	private frames: string[] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
	private frameIndex: number = 0;
	private interval: ReturnType<typeof setInterval> | null = null;
	private isRunning: boolean = false;

	constructor(message: string = "Working...") {
		this.message = message;
	}

	start(): void {
		if (this.isRunning) return;

		this.isRunning = true;
		this.frameIndex = 0;

		this.interval = setInterval(() => {
			process.stdout.write(
				`\r${SPINNER_BLUE}${this.frames[this.frameIndex]}${RESET} ${this.message}`,
			);
			this.frameIndex = (this.frameIndex + 1) % this.frames.length;
		}, 100);
	}

	stop(): void {
		if (!this.isRunning) return;

		if (this.interval) {
			clearInterval(this.interval);
			this.interval = null;
		}

		process.stdout.write(`\r${" ".repeat(this.message.length + 5)}\r`);
		this.isRunning = false;
	}

	finish(successMessage: string = "Complete"): void {
		this.stop();
		console.log(`${SUCCESS_GREEN}\u2713${RESET} ${successMessage}`);
	}
}
