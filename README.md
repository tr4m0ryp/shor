# Shor

> Readme coming soon.

Shor is an autonomous offensive-security engine for web apps: a multi-agent pipeline — recon, source-grounded vulnerability analysis, adversarial screening, and live exploitation — that proves every finding by replaying its PoC. Built to break web apps the way a real attacker would, and surface only validated, exploitable bugs.

## Tooling

Shor's agents don't just reason — they wield 30+ real offensive-security tools, exposed to the model as invokable **skills**. So recon, exploitation, and static analysis run on the same industry tooling a human pentester reaches for:

- **Recon:** nmap · naabu · httpx · katana · ffuf · arjun · paramspider · subfinder · dnsx · gau · waybackurls · kxss · wafw00f · nuclei
- **Exploitation:** sqlmap · commix · nosqli · xsstrike · dalfox · ssrfmap · sstimap · jwt_tool · hydra · interactsh-client · playwright
- **Static analysis:** semgrep · gitleaks · trufflehog · osv-scanner · trivy

## Acknowledgements

Shor's discovery-and-verification pipeline ports ideas from Anthropic's defending-code reference harness, and its agent design follows Anthropic's *Building Effective Agents* patterns. It also builds on prior work in autonomous, validated penetration testing:

- **Anthropic — Defending code reference harness** — the discovery + verification pipeline Shor is based on ([repo](https://github.com/anthropics/defending-code-reference-harness), [Claude Code security](https://www.anthropic.com/news/claude-code-security)).
- **Anthropic — [Building Effective Agents](https://www.anthropic.com/research/building-effective-agents)** — the orchestrator-workers and evaluator–optimizer patterns the pipeline is built on.
- **[XBOW](https://xbow.com)** — validated, safe-PoC findings and its public challenge benchmark.
- **[PentestGPT](https://github.com/GreyDGL/PentestGPT)** — LLM-driven specialist-sub-agent pentest orchestration.
- **[Shannon](https://github.com/KeygraphHQ/shannon)** — open-source autonomous web-pentest agent.
- **Strix** and **HexStrike AI** — additional prior art in agentic penetration testing.

## License

Shor is **source-available**, licensed under the [PolyForm Noncommercial License 1.0.0](./LICENSE) — **not** an OSI open-source license.

- **You may** use, modify, fork, and share Shor freely for any **noncommercial** purpose, as long as you keep the copyright and `Required Notice:` lines (see [`NOTICE`](./NOTICE)) and credit *"Based on Shor by Keygraph, Inc."*
- **You may not** sell it, bundle it into a paid product, or run it as a paid/hosted service **without a commercial license**.

Copyright (c) 2025-2026 Keygraph, Inc. Commercial licensing enquiries: see [`NOTICE`](./NOTICE).
