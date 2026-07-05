"""Server-to-server client for Shor's ``/external/*`` control plane.

The connector re-implements NO scanning — it orchestrates the existing engine
endpoints. Every request carries the engine trigger token as a bearer; that
token is never logged and never returned in tool output. Non-2xx responses are
raised as ``ToolError`` carrying the engine's error message (already secret-
scrubbed by the engine), so the model sees a clean failure, not a stack trace.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastmcp.exceptions import ToolError

from .config import get_config

_client: httpx.AsyncClient | None = None


def _http() -> httpx.AsyncClient:
    """Lazily build the shared HTTP client (auth header baked in)."""
    global _client
    if _client is None:
        cfg = get_config()
        _client = httpx.AsyncClient(
            base_url=cfg.shor_base_url,
            headers={"authorization": f"Bearer {cfg.engine_trigger_token}"},
            timeout=30.0,
        )
    return _client


async def _call(method: str, path: str, json: dict | None = None) -> dict[str, Any]:
    """Call a control-plane endpoint; raise ToolError on transport/HTTP failure."""
    try:
        resp = await _http().request(method, path, json=json)
    except httpx.HTTPError as exc:
        raise ToolError(f"could not reach the Shor control plane: {exc}") from exc
    body: dict[str, Any] = {}
    if resp.content:
        try:
            body = resp.json()
        except ValueError:
            body = {}
    if resp.status_code >= 400:
        msg = body.get("error") if isinstance(body, dict) else None
        raise ToolError(f"Shor rejected the request ({resp.status_code}): {msg or resp.text[:200]}")
    return body


async def launch(engagement_id: str, authorization_token: str, roe: dict) -> dict[str, Any]:
    """Token-gated black-box launch (forwards the signed RoE + launch token)."""
    return await _call(
        "POST",
        "/external/launch",
        {"engagementId": engagement_id, "authorizationToken": authorization_token, "roe": roe},
    )


async def list_active_runs() -> list[dict[str, Any]]:
    """List the tenant's in-flight runs (pending + running)."""
    body = await _call("GET", "/external/scans")
    runs = body.get("runs", [])
    return runs if isinstance(runs, list) else []


async def get_scan(scan_id: str) -> dict[str, Any]:
    """Read-only status snapshot for one scan."""
    return await _call("GET", f"/external/scans/{scan_id}")


async def cancel_scan(scan_id: str) -> dict[str, Any]:
    """Stop a running scan (operator kill switch). Activity-reducing, ungated."""
    return await _call("POST", f"/external/scans/{scan_id}/cancel")


async def get_findings(scan_id: str) -> list[dict[str, Any]]:
    """Read-only list of a scan's finding records."""
    body = await _call("GET", f"/external/scans/{scan_id}/findings")
    findings = body.get("findings", [])
    return findings if isinstance(findings, list) else []


async def get_report(scan_id: str) -> Any:
    """Read-only finalized executive report for a scan (None until finalized)."""
    body = await _call("GET", f"/external/scans/{scan_id}/report")
    return body.get("report")


async def get_attack_surface(scan_id: str) -> Any:
    """Read-only attack-surface document (scenarios + kill chains) for a scan."""
    body = await _call("GET", f"/external/scans/{scan_id}/attack-surface")
    return body.get("attackSurface")


async def list_projects() -> list[dict[str, Any]]:
    """Read-only list of the tenant's projects (targets)."""
    body = await _call("GET", "/external/projects")
    projects = body.get("projects", [])
    return projects if isinstance(projects, list) else []


async def get_scan_history(project_id: str) -> list[dict[str, Any]]:
    """Read-only list of a project's scans, newest first."""
    body = await _call("GET", f"/external/projects/{project_id}/scans")
    scans = body.get("scans", [])
    return scans if isinstance(scans, list) else []


async def share(project_id: str) -> dict[str, Any]:
    """Mint/read the project's read-only guest link."""
    return await _call("POST", f"/external/projects/{project_id}/share")
