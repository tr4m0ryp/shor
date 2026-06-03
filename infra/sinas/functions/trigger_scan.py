# Copyright (C) 2025 Keygraph, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3
# as published by the Free Software Foundation.
#
# Sinas function: pentest/trigger_scan
#
# Deterministic, no LLM. Starts a scan on the shor engine and mirrors the
# engine-minted scan id into the pentest/scans store.
#
# Design T8 (engine mints all ids): call the `engine` connector FIRST, take the
# engine-returned {scan_id}, and ONLY THEN record pentest/scans/{scan_id}. This
# replaces the previous behaviour where trigger_scan minted its own uuid4 — a
# self-minted id would diverge from the engine row once the web-layer mirror
# writes the engine's id (T2/T3).
#
# Auth channels (T7): Sinas -> engine is bearer, carried by the `engine`
# connector (SHOR_ENGINE_TRIGGER_TOKEN); this function never sees that token.
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
# OpenAPI (GET /openapi.json) before relying on it; if it differs, change
# ONLY this template — both functions import it.
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
    """Start a scan on the engine, then mirror the engine-minted scan id.

    input_data: { "projectId": str, "ref": str (optional) }
    returns:    { "scanId": str, "status": str }
    """
    project_id = input_data["projectId"]
    ref = input_data.get("ref")

    # 1) Engine FIRST — POST /external/scans {projectId, ref?} -> {scanId,status}
    start_input = {"projectId": project_id}
    if ref:
        start_input["ref"] = ref
    started = _call_engine(context["access_token"], "start_scan", start_input)

    # The engine contract returns camelCase {scanId,status}; tolerate snake_case
    # in case the connector passes the body through verbatim.
    scan_id = started.get("scanId") or started.get("scan_id")
    status = started.get("status") or "queued"
    if not scan_id:
        raise ValueError(f"engine start_scan returned no scan id: {started!r}")

    # 2) THEN record pentest/scans/{scan_id} with the engine-minted id.
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    _record_state(
        context["access_token"],
        "scans",
        scan_id,
        {
            "scanId": scan_id,
            "projectId": project_id,
            "ref": ref,
            "status": status,
            "source": "sinas:trigger_scan",
            "updatedAt": now,
        },
        tags=[status],
    )

    return {"scanId": scan_id, "status": status}
