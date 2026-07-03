// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The committed flagship starter set: landmark techniques hand-encoded into seed
 * exemplars (`noveltyTier: 'flagship'`). Every field is authored in our own words
 * from public research; each `provenance.url` credits the canonical source. These
 * are the highest-signal seeds — the ones worth carrying regardless of any
 * external catalogue — anchored by Netflix's "Starting the Avalanche"
 * algorithmic-complexity DoS and a spread of PortSwigger Top-10 (2024/2025)
 * winners and nominees.
 */

import type { SeedExemplar } from "./types.js";

/** The hand-encoded flagship exemplars. */
export const FLAGSHIP_SEEDS: readonly SeedExemplar[] = [
	{
		technique: "Algorithmic-complexity DoS (Starting the Avalanche)",
		aliases: ["ReDoS-class resource exhaustion", "complexity attack"],
		preconditions:
			"A hot request path performs super-linear work whose cost is driven by attacker-controlled input size or shape.",
		rootCause:
			"Unbounded computational complexity on a shared hot path; no cost ceiling or input-size guard before the expensive operation.",
		source: "attacker-controlled request parameter (size/shape)",
		sink: "expensive per-request operation (sort/regex/allocation/serialization)",
		probeSignal:
			"Response time and CPU/memory climb super-linearly as crafted input grows; a few small requests degrade the whole service.",
		pocSkeleton:
			"# escalate input that drives worst-case cost\nfor n in [100, 1000, 10000, 100000]:\n    t = time_request(endpoint, craft_worst_case(n))\n    record(n, t)  # look for super-linear t(n)",
		cwe: "CWE-400",
		tags: ["dos", "complexity", "resource-exhaustion", "cwe-407"],
		noveltyTier: "flagship",
		provenance: {
			source: "Netflix Technology Blog",
			url: "https://netflixtechblog.com/starting-the-avalanche-640e69b14a06",
			date: "2022",
		},
	},
	{
		technique: "Unicode best-fit / normalization exploitation (WorstFit)",
		aliases: ["best-fit mapping abuse", "WorstFit"],
		preconditions:
			"A boundary normalizes or best-fit-maps Unicode to ASCII AFTER a security check runs on the original bytes.",
		rootCause:
			"Validation and interpretation disagree on the string: a benign-looking character is later folded into a dangerous ASCII one, defeating the earlier filter.",
		source: "attacker-supplied Unicode in a path/arg/filename",
		sink: "downstream ASCII consumer (shell, argument parser, path resolver)",
		probeSignal:
			"A full-width or homoglyph character passes validation but the downstream component behaves as if the ASCII equivalent was supplied.",
		pocSkeleton:
			"# fullwidth chars that best-fit to ASCII metacharacters\npayload = '\\uFF0F..\\uFF0Fetc\\uFF0Fpasswd'  # maps toward /../etc/passwd\nsend(endpoint, param=payload)",
		cwe: "CWE-176",
		tags: ["unicode", "best-fit", "argument-injection", "cwe-88"],
		noveltyTier: "flagship",
		provenance: {
			source: "DEVCORE / Orange Tsai",
			url: "https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-of-windows-ansi/",
			date: "2025",
		},
	},
	{
		technique: "Parser differential via email address structure",
		aliases: ["Splitting the email atom", "email parser confusion"],
		preconditions:
			"One component validates an email/identifier and a different component re-parses it, with disagreeing grammars (comments, encoded words, quoting).",
		rootCause:
			"Two parsers extract different domains/values from the same string, so an allowlist check binds a different value than the consumer acts on.",
		source: "attacker-controlled email/identifier field",
		sink: "domain-based access decision or message routing",
		probeSignal:
			"An address the validator reads as an allowed domain is delivered/authorized as a different, attacker-chosen domain.",
		pocSkeleton:
			"# structured local-part / encoded-word smuggles a second domain\naddr = 'victim@allowed.com(@attacker.com)'\nregister(addr)  # validator sees allowed.com, mailer uses attacker.com",
		cwe: "CWE-436",
		tags: [
			"parser-differential",
			"email",
			"access-control",
			"interpretation-conflict",
		],
		noveltyTier: "flagship",
		provenance: {
			source: "PortSwigger Research (Gareth Heyes)",
			url: "https://portswigger.net/research/splitting-the-email-atom",
			date: "2024",
		},
	},
	{
		technique: "Next.js cache poisoning via chained response mutation",
		aliases: ["stale elixir", "SSG/ISR cache poisoning"],
		preconditions:
			"A CDN/framework caches a response whose key omits a header or path quirk that the origin lets an attacker influence.",
		rootCause:
			"Cache key and cacheability decision diverge from the factors that actually vary the response, so an attacker-shaped response is stored and served to others.",
		source: "unkeyed request input (header, extension, or trailing segment)",
		sink: "shared CDN / framework data-cache entry",
		probeSignal:
			"A crafted request causes a poisoned or wrong-variant response to be returned to subsequent normal visitors.",
		pocSkeleton:
			"# unkeyed header/extension shifts the cached variant\nGET /_next/data/build/page.json HTTP/1.1\nX-Unkeyed-Header: attacker\n# reload as a victim and observe the poisoned entry",
		cwe: "CWE-525",
		tags: ["cache-poisoning", "nextjs", "cdn", "cwe-444"],
		noveltyTier: "flagship",
		provenance: {
			source: "zhero_web_security",
			url: "https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir",
			date: "2025",
		},
	},
	{
		technique: "SSRF filter bypass via HTTP redirect follow",
		aliases: ["redirect-loop SSRF", "open-redirect SSRF pivot"],
		preconditions:
			"A server-side fetcher validates the initial URL against an allowlist but transparently follows 3xx redirects to the final host.",
		rootCause:
			"The allowlist check runs once on the first hop while the HTTP client keeps following redirects, letting an attacker-controlled endpoint bounce the fetch to an internal target.",
		source: "attacker-controlled fetch URL pointing at an allowed host",
		sink: "internal metadata/service endpoint reached after a redirect",
		probeSignal:
			"An allowed URL that 302-redirects to 169.254.169.254 or localhost returns internal content, proving the fetcher ignored the redirect target policy.",
		pocSkeleton:
			"# attacker host issues a redirect to an internal address\n# GET https://allowed.example/fetch?url=https://evil.tld/r\n# evil.tld/r -> 302 Location: http://169.254.169.254/latest/meta-data/",
		cwe: "CWE-918",
		tags: ["ssrf", "redirect", "allowlist-bypass", "cloud-metadata"],
		noveltyTier: "flagship",
		provenance: {
			source: "PortSwigger Web Security Academy",
			url: "https://portswigger.net/web-security/ssrf",
			date: "2024",
		},
	},
	{
		technique: "ORM relational-filter data leak (Plormbing)",
		aliases: ["ORM leak", "relational filter injection"],
		preconditions:
			"User-controlled keys/operators reach an ORM filter, letting a caller traverse relations or apply lookups on fields they cannot read.",
		rootCause:
			"The ORM trusts attacker-shaped filter keys, so predicate-based oracles leak values of unexposed columns one comparison at a time.",
		source: "attacker-controlled query/filter parameters",
		sink: "ORM query builder (relation traversal + lookup operators)",
		probeSignal:
			"Filtering on an unexposed field (e.g. password__startswith=a) changes the result set, forming a boolean oracle over hidden data.",
		pocSkeleton:
			"# boolean-oracle exfiltration through a relational lookup\nfor c in charset:\n    hit = GET(f'/api/items?owner__secret__startswith={known+c}')\n    if hit: known += c; break",
		cwe: "CWE-200",
		tags: ["orm", "information-disclosure", "django", "operator-injection"],
		noveltyTier: "flagship",
		provenance: {
			source: "elttam",
			url: "https://www.elttam.com/blog/plormbing-your-django-orm/",
			date: "2024",
		},
	},
	{
		technique: "Apache HTTP Server confusion attacks",
		aliases: [
			"filename confusion",
			"DocumentRoot confusion",
			"handler confusion",
		],
		preconditions:
			"Directives, path normalization, and handler selection disagree about what a request path means across Apache modules.",
		rootCause:
			"Ambiguous internal representation of the request path lets a crafted URL be treated as one resource for authorization and another for handling.",
		source: "attacker-crafted request path with encoded/appended segments",
		sink: "module dispatch / authorization mismatch (mod_rewrite, handlers, files)",
		probeSignal:
			"A path that should be denied is served, or a static path is executed by a handler it should never reach.",
		pocSkeleton:
			"# path/handler ambiguity exposes a protected resource\nGET /admin.php%3Fx.jpg HTTP/1.1  # authz sees .jpg, handler runs .php",
		cwe: "CWE-436",
		tags: ["apache", "path-confusion", "authz-bypass", "web-server"],
		noveltyTier: "flagship",
		provenance: {
			source: "Orange Tsai / DEVCORE",
			url: "https://blog.orange.tw/posts/2024-08-confusion-attacks-en/",
			date: "2024",
		},
	},
	{
		technique: "Web race conditions (single-packet attack)",
		aliases: ["Smashing the state machine", "limit-overrun race"],
		preconditions:
			"A multi-step server operation has a window where two concurrent requests observe the same pre-update state.",
		rootCause:
			"Missing atomicity/locking around a check-then-act sequence lets parallel requests each pass a one-time or limited check.",
		source: "concurrent duplicate requests (near-simultaneous)",
		sink: "check-then-act state transition (redeem, transfer, promote)",
		probeSignal:
			"Firing N requests in one burst yields more successes than the intended limit (e.g. a single-use coupon applied twice).",
		pocSkeleton:
			"# single-packet burst to hit the same pre-update state\nreqs = [build(endpoint) for _ in range(30)]\nsend_synchronized(reqs)  # count > allowed limit == race",
		cwe: "CWE-362",
		tags: ["race-condition", "toctou", "concurrency", "business-logic"],
		noveltyTier: "flagship",
		provenance: {
			source: "PortSwigger Research (James Kettle)",
			url: "https://portswigger.net/research/smashing-the-state-machine",
			date: "2023",
		},
	},
	{
		technique: "Practical web timing attacks",
		aliases: ["Listen to the whispers", "server-side timing oracle"],
		preconditions:
			"A response's timing depends on a secret-conditioned code path (record existence, injection reaching a backend, scoped work).",
		rootCause:
			"Non-constant-time handling leaks a boolean/branch through latency; modern single-packet timing makes sub-millisecond gaps measurable over the internet.",
		source: "attacker-controlled input feeding a secret-dependent branch",
		sink: "response latency (the timing oracle)",
		probeSignal:
			"A statistically significant, repeatable timing delta between two input classes reveals the hidden state.",
		pocSkeleton:
			"# compare timing distributions for two input classes\nA = [time(req(x_true)) for _ in range(200)]\nB = [time(req(x_false)) for _ in range(200)]\nassert significant(A, B)  # timing oracle",
		cwe: "CWE-208",
		tags: ["timing-attack", "side-channel", "oracle", "info-leak"],
		noveltyTier: "flagship",
		provenance: {
			source: "PortSwigger Research (James Kettle)",
			url: "https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work",
			date: "2024",
		},
	},
	{
		technique: "Web cache deception",
		aliases: ["Gotta cache 'em all", "path-confusion caching"],
		preconditions:
			"A CDN caches by static-looking suffix while the origin ignores the appended path segment and serves dynamic, per-user content.",
		rootCause:
			"Cache and origin disagree on whether a URL is static, so a victim's authenticated response is stored under an attacker-reachable cache key.",
		source: "attacker-crafted URL with a fake static suffix",
		sink: "shared cache entry holding another user's private response",
		probeSignal:
			"Requesting victimprofile/nonexistent.css caches the victim's private page and lets the attacker retrieve it unauthenticated.",
		pocSkeleton:
			"# lure victim to a cache-primed URL, then read the cached copy\n# victim GET /account/wallet/x.css (origin serves wallet, CDN caches)\n# attacker GET /account/wallet/x.css -> private data",
		cwe: "CWE-525",
		tags: ["cache-deception", "cdn", "path-confusion", "info-disclosure"],
		noveltyTier: "flagship",
		provenance: {
			source: "PortSwigger Research (Martin Doyhenard)",
			url: "https://portswigger.net/research/gotta-cache-em-all",
			date: "2024",
		},
	},
	{
		technique: "WAF bypass via phantom cookie parsing",
		aliases: ["phantom $Version cookie", "cookie parser differential"],
		preconditions:
			"A WAF and the origin parse cookies with different grammars (RFC 2109 $Version, quoting, or delimiter handling).",
		rootCause:
			"The WAF and application extract different cookie values from the same header, so a payload invisible to the WAF is honored by the app.",
		source: "attacker-crafted Cookie header with legacy quoting/attributes",
		sink: "application cookie consumer downstream of the WAF",
		probeSignal:
			"A cookie value carrying a blocked payload passes the WAF untouched yet arrives intact at the application.",
		pocSkeleton:
			'# $Version quoting hides the real value from the WAF\nCookie: $Version=1; sid="legit"; evil="\' OR 1=1--"',
		cwe: "CWE-436",
		tags: ["waf-bypass", "cookie", "parser-differential", "http"],
		noveltyTier: "flagship",
		provenance: {
			source: "PortSwigger Research",
			url: "https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie",
			date: "2024",
		},
	},
	{
		technique: "Next.js middleware authorization bypass",
		aliases: ["corrupt middleware", "CVE-2025-29927"],
		preconditions:
			"Access control is enforced only in Next.js middleware, and the request can influence the internal header that controls middleware execution.",
		rootCause:
			"An internal control header (x-middleware-subrequest) is attacker-spoofable, letting a request skip the middleware that performs the authorization check.",
		source: "attacker-supplied internal control header",
		sink: "middleware-gated route reached without its auth check",
		probeSignal:
			"Adding the spoofed control header grants access to a route that otherwise redirects/401s.",
		pocSkeleton:
			"# spoof the internal header to skip auth middleware\nGET /admin HTTP/1.1\nx-middleware-subrequest: middleware:middleware:middleware:middleware:middleware",
		cwe: "CWE-285",
		tags: ["nextjs", "authz-bypass", "middleware", "cwe-306"],
		noveltyTier: "flagship",
		provenance: {
			source: "zhero_web_security",
			url: "https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware",
			date: "2025",
		},
	},
];

/** Return the committed flagship starter set (defensive copy of the array). */
export function flagshipManifest(): SeedExemplar[] {
	return [...FLAGSHIP_SEEDS];
}
