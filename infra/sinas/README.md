<!--
Copyright (C) 2025 Keygraph, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
as published by the Free Software Foundation.
-->

# Aegis ↔ Sinas backend resources — apply runbook

Provisions the net-new / updated **`pentest`** backend resources for the
two-way integration on the group instance
`https://via-12.sinas.wearebrain.com` (Management API under `/api/v1/`).

The orchestrator applies these with an **admin token** at acceptance. Nothing
here calls via-12; these are committed artifacts only.

## What this provisions

| Resource | Kind | Change |
|---|---|---|
| `pentest/projects` | store | **net-new** (4th mirror store beside scans/findings/reports) |
| `pentest/engine` | connector | **repointed** off the `https://ENGINE-HOST.invalid` placeholder → `${{ vars.ENGINE_BASE_URL }}`, `auth: none` → **bearer** |
| `pentest/trigger_scan` | function | **reordered** — engine mints the id first (T8), no more self-minted uuid |
| `pentest/create_project` | function | **net-new** — engine mints the project id (T8/T9) |
| `pentest/finalizer` | agent | **model swap** only → `anthropic/claude-sonnet-4.6` |

Out of scope (sibling task): the `report-view` **component** + registering it.
`spec.components` is left an explicit empty list for that task to append to.

## Files

```
infra/sinas/
  sinas-package.yaml            GENERATED installable package (do not hand-edit)
  assemble.py                   regenerates the package from the fragments below
  functions/trigger_scan.py     canonical source (py_compile-verified)
  functions/create_project.py   canonical source (py_compile-verified)
  connectors/engine.yaml        canonical connector fragment
  stores/projects.yaml          canonical store fragment
  agents/finalizer.patch.yaml   model-only PATCH (NOT in the package — see below)
```

`sinas-package.yaml` is a **build artifact**: its `spec.functions[].code` and the
connector/store blocks are assembled verbatim from the fragments, so there is
exactly one source of truth per resource.

- Regenerate after editing any fragment: `python3 infra/sinas/assemble.py`
- Verify it is not stale (CI / pre-apply): `python3 infra/sinas/assemble.py --check`

## Schema decision

Native **SinasPackage** (`apiVersion: sinas.co/v1`), per the
`sinas-platform/skills` → `sinas-package-author` skill. The schema applied
cleanly for stores / connectors / functions / manifest, so **no API
provisioning script was needed** for those. The one resource the package does
**not** carry is the finalizer model swap (reason below).

## Install-time variables (fill at apply; nothing real is committed)

The package declares two `spec.variables`; Sinas substitutes `${{ vars.NAME }}`
**before persistence** (this is Sinas's own templating, not Jinja2):

| Variable | Type | Fill with |
|---|---|---|
| `ENGINE_BASE_URL` | `text` | public base URL of the hosted **aegis-web** control plane (e.g. `https://aegis-web-…run.app`) |
| `ENGINE_TRIGGER_TOKEN` | `secret` | the shared **`AEGIS_ENGINE_TRIGGER_TOKEN`** (same value the engine validates) |

`ENGINE_TRIGGER_TOKEN` is type `secret`: installing creates a **write-only**
Sinas secret. Sinas secrets are set once and never read back (T7) — supply it at
install time; re-installs do not need it again unless rotating.

## Apply order

> Auth: engine→Sinas uses `X-API-Key`; **Sinas→engine uses bearer**
> (`Authorization: Bearer <AEGIS_ENGINE_TRIGGER_TOKEN>`), carried by the
> `engine` connector — never put that token in the browser/component bundle.

1. **Pre-flight (no writes).** From a checkout with `.sinas/config.json`:
   ```bash
   python3 infra/sinas/assemble.py --check     # package matches fragments
   sinas validate                              # validate the package YAML
   ```
2. **Preview the package.** Dry-run; share the diff:
   ```bash
   sinas preview
   ```
   (Equivalent API: `POST /api/v1/packages/preview`.)
3. **Install the package** (creates `pentest/projects`, repoints+bearers
   `pentest/engine`, installs `trigger_scan` + reorders to engine-minted id,
   installs `create_project`). You will be prompted for `ENGINE_BASE_URL` and
   the `ENGINE_TRIGGER_TOKEN` secret:
   ```bash
   sinas install
   ```
   (Equivalent API: `POST /api/v1/packages/install` with the two variables.)
4. **Finalizer model swap — PATCH, do NOT reinstall the agent.** The agent
   already exists with an **enforced `output_schema`**; recreating it would mean
   re-supplying that schema, so the package deliberately omits it. Apply a
   targeted PATCH instead (agents do **not** hit the component hang):
   ```bash
   TOKEN=$(jq -r .admin_token .sinas/config.json)
   URL=$(jq -r .instance_url .sinas/config.json)
   curl -X PATCH -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     "$URL/api/v1/agents/pentest/finalizer" \
     -d '{"model": "anthropic/claude-sonnet-4.6"}'
   ```
   Source of truth: `agents/finalizer.patch.yaml`. Leave `output_schema`,
   `system_prompt`, and `enabled_stores` unchanged.
5. **Verify the manifest is satisfied:**
   ```bash
   sinas status
   ```

## via-12 gotcha — components apply by recreate-via-POST, never PUT

Component **`PUT`/`DELETE` hang** on via-12. This task ships **no** component,
but the sibling task that adds `report-view` (and any later component edit) MUST
**recreate via `POST`** under a fresh name rather than `PUT`-ing an existing one:

```bash
# WRONG on via-12 — hangs:
#   curl -X PUT  .../api/v1/components/pentest/report-view -d @component.json
# RIGHT — recreate by POST (delete-then-create or new name):
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "$URL/api/v1/components" -d @component.json
```

When that task lands, it appends the component to `spec.components` in
`sinas-package.yaml` (with `enabledFunctions: [pentest/trigger_scan,
pentest/create_project]` and the `projects`/`scans`/`findings`/`reports`
stores) and adds the matching `requiredResources` entry to the manifest — no
other section changes — but it should still apply that component by POST on
via-12 if `sinas install` proxies a PUT for updates.

## Apply-time verification flags

- **Connector-invocation path (functions).** Both functions call the engine
  connector via `POST /connectors/{ns}/{name}/{op}/execute` — modelled on the
  documented query form `/queries/{ns}/{name}/execute`. The public docs OpenAPI
  is a stub, so this could not be confirmed live. **Before/after install,
  confirm the path against the via-12 runtime spec** (`curl -s "$URL/openapi.json"
  | jq '.paths | keys' | grep connectors`). If it differs, change only the
  `CONNECTOR_EXEC_PATH` constant in both `functions/*.py`, then
  `python3 infra/sinas/assemble.py` and re-install.
- **Connector body parameter.** Operations declare one `body` (`in: body`)
  parameter; the functions send the op input under both `input` and `body` keys
  for resilience. If the runtime rejects one key, drop it in `_call_engine` and
  reassemble.
- **Connector `auth` shape.** Used `auth: { type: bearer, secret: <var> }` per
  the skill. If the instance expects a different bearer field name, adjust
  `connectors/engine.yaml` and reassemble.

## Notes

- Store writes use the proven contract from `apps/worker` `sinas-finalization.ts`:
  `POST /stores/{ns}/{store}/states` with `{key, value, tags}`, keyed by the
  engine-minted id; values carry `updatedAt` for last-writer-wins idempotency.
- No secrets, tokens, or hosts are committed — placeholders only.
