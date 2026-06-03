# Copyright (C) 2025 Keygraph, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3
# as published by the Free Software Foundation.
#
# Sinas function: pentest/create_project
#
# Deterministic, no LLM. Creates a project on the aegis engine and mirrors the
# engine-minted project id into the pentest/projects store.
#
# Design T8/T9 (engine mints all ids; white-box ingest is engine-side): call the
# `engine` connector create_project FIRST, take the engine-returned {project_id},
# and ONLY THEN record pentest/projects/{project_id}. For white-box, repoRef is
# one of GET /external/github/repos — the engine pulls the code with its stored
# GitHub token; Sinas never handles the repo or the token.
#
# Auth channels (T7): Sinas -> engine is bearer, carried by the `engine`
# connector (AEGIS_ENGINE_TRIGGER_TOKEN); this function never sees that token.
# The store write uses the per-execution Sinas access token in
# context["access_token"].

import datetime
import json
import urllib.request

# --- Apply-time-verifiable runtime paths -----------------------------------
# Sinas runtime base URL reachable from inside a function sandbox. The
# package-author skill documents this host for the preinstalled SDK.
SINAS_RUNTIME_BASE = "http://host.docker.internal:8000"

# Connector-operation invocation path. The skill documents the query form
# ("/queries/{ns}/{name}/execute"); the connector form is modelled on it.
# FLAG (apply-time): confirm this exact path against the via-12 runtime
# OpenAPI (GET /openapi.json); if it differs, change ONLY this template.
CONNECTOR_EXEC_PATH = "/connectors/{ns}/{name}/{op}/execute"

# Store state upsert. Proven on via-12 by apps/worker sinas-finalization.ts:
# POST /stores/{ns}/{store}/states with {key, value, tags}.
STORE_STATES_PATH = "/stores/{ns}/{store}/states"

NAMESPACE = "pentest"
ENGINE_CONNECTOR = "engine"


def _post(path, token, payload):
    """POST JSON to the Sinas runtime API with the execution access token."""
    url = f"{SINAS_RUNTIME_BASE}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def _call_engine(token, operation, op_input):
    """Invoke an `engine` connector operation; return its parsed JSON result."""
    path = CONNECTOR_EXEC_PATH.format(ns=NAMESPACE, name=ENGINE_CONNECTOR, op=operation)
    # Connector operations declare a single `body` parameter (in: body); the
    # runtime accepts it under "input". Both keys are sent for resilience to the
    # exact runtime contract; the engine endpoint reads the JSON body either way.
    return _post(path, token, {"input": op_input, "body": op_input})


def _record_state(token, store, key, value, tags=None):
    """Upsert one state into a pentest store, keyed by the engine-minted id."""
    path = STORE_STATES_PATH.format(ns=NAMESPACE, store=store)
    payload = {"key": key, "value": value}
    if tags:
        payload["tags"] = tags
    return _post(path, token, payload)


def handler(input_data, context):
    """Create a project on the engine, then mirror the engine-minted id.

    input_data: {
        "name": str, "targetUrl": str,
        "mode": "blackbox" | "whitebox",
        "repoRef": str (optional; required by the engine for whitebox)
    }
    returns: { "projectId": str }
    """
    name = input_data["name"]
    target_url = input_data["targetUrl"]
    mode = input_data["mode"]
    repo_ref = input_data.get("repoRef")

    # 1) Engine FIRST — POST /external/projects
    #    {name,targetUrl,mode,repoRef?} -> {projectId}
    create_input = {"name": name, "targetUrl": target_url, "mode": mode}
    if repo_ref:
        create_input["repoRef"] = repo_ref
    created = _call_engine(context["access_token"], "create_project", create_input)

    # Engine contract returns camelCase {projectId}; tolerate snake_case in case
    # the connector passes the body through verbatim.
    project_id = created.get("projectId") or created.get("project_id")
    if not project_id:
        raise ValueError(f"engine create_project returned no project id: {created!r}")

    # 2) THEN record pentest/projects/{project_id} with the engine-minted id.
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    _record_state(
        context["access_token"],
        "projects",
        project_id,
        {
            "projectId": project_id,
            "name": name,
            "targetUrl": target_url,
            "mode": mode,
            "repoRef": repo_ref,
            "source": "sinas:create_project",
            "updatedAt": now,
        },
        tags=[mode],
    )

    return {"projectId": project_id}
