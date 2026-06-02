// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { Authentication, Rule } from "../types/config.js";

export const sanitizeRule = (rule: Rule): Rule => {
	return {
		description: rule.description.trim(),
		type: rule.type.toLowerCase().trim() as Rule["type"],
		url_path: rule.url_path.trim(),
	};
};

export const sanitizeAuthentication = (
	auth: Authentication,
): Authentication => {
	return {
		login_type: auth.login_type
			.toLowerCase()
			.trim() as Authentication["login_type"],
		login_url: auth.login_url.trim(),
		credentials: {
			username: auth.credentials.username.trim(),
			password: auth.credentials.password,
			...(auth.credentials.totp_secret && {
				totp_secret: auth.credentials.totp_secret.trim(),
			}),
		},
		...(auth.login_flow && {
			login_flow: auth.login_flow.map((step) => step.trim()),
		}),
		success_condition: {
			type: auth.success_condition.type
				.toLowerCase()
				.trim() as Authentication["success_condition"]["type"],
			value: auth.success_condition.value.trim(),
		},
	};
};
