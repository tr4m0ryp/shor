---
name: sstimap
description: "[exploit] Detect and exploit Server-Side Template Injection across many engines (Jinja2, Twig, Freemarker, etc.). Reach for it when input is reflected into a template and a polyglot probe hints at evaluation."
---

# SSTImap — server-side template injection

`SSTImap` (Python; pinned git clone, run in place from `/opt/shor/tools/SSTImap`,
e.g. `python sstimap.py`). Maintained py3 successor to tplmap. Detects the
template engine and escalates SSTI to code/command execution where the engine
allows. **Live → exploitation phase.**

## When to reach for it
- When a parameter's value appears evaluated (e.g. `{{7*7}}` → `49`, `${7*7}`,
  `<%= 7*7 %>`) or recon shows a server-side template render of user input.
- To identify the specific engine and prove impact minimally.

## Key flags
- `-u "<url>"` target; `-d 'k=v'` POST data; `--cookie`, `-H` for auth.
- `-p <param>` focus a parameter; `-m GET|POST`.
- `-e <engine>` force an engine (else auto-detect across plugins).
- `-l <level>` detection depth; `-o`/`--os-cmd "<cmd>"` run a single OS command
  (use a harmless one); `-S`/`--os-shell` interactive shell (avoid).
- `--tpl-shell` template-eval shell (avoid for automated proof).

## Safe invocation
```bash
# Auto-detect engine on one param; if exploitable, prove with a harmless command
sstimap -u "https://target.example.com/greet?name=test" -p name --os-cmd "id"
```

## Evidence to capture
- Detected engine + the evaluating payload (e.g. `{{7*7}}`→`49`), exact request,
  and the **benign** command output proving execution. Map to CWE-1336 / CWE-94.
- The minimal arithmetic-eval reflection alone proves SSTI — escalate only as far
  as one harmless command.

## Scope & rate caveats
- Target ONLY the in-scope endpoint. Stop at minimal proof (eval reflection, or one
  read-only command like `id`); do NOT open shells, read files in bulk, or pivot
  unless the Rules of Engagement explicitly allow it.
- Pinned to a `tools.lock` SHA for reproducibility — run in place, don't `pip`-pull.
- Throttle requests; SSTI detection fans out payloads per engine plugin.
