"""Run-lifecycle tools: start, list, poll, cancel.

``start_blackbox_run`` is the ONLY start path and structurally requires a
human-minted launch token, so a routine holding these tools still cannot start
an unauthorized scan. ``cancel_run`` only ever REDUCES activity (it stops a run),
so it needs no launch token — the connector's engine bearer authorizes it.
"""

from __future__ import annotations

from typing import Any

from .. import shor_client


async def start_blackbox_run(
    engagement_id: str,
    authorization_token: str,
    roe: dict,
) -> dict[str, Any]:
    """Start a black-box security scan.

    REQUIRES a single-use ``authorization_token`` minted by a human approver for
    THIS engagement and THIS exact RoE; the run is rejected otherwise. The RoE is
    the signed DEFAULT-DENY allowlist the engine enforces on every network action.

    Args:
        engagement_id: The signed engagement this run belongs to.
        authorization_token: Single-use launch token from the human approval step.
            The routine cannot mint this — obtain it from the approver.
        roe: The signed DEFAULT-DENY Rules of Engagement, e.g.
            {"version": 1, "targetUrl": "https://app.example.com",
             "allowedHosts": [{"host": "app.example.com", "schemes": ["https"]}]}.

    Returns:
        {"projectId": ..., "scanId": ..., "status": ...}
    """
    r = await shor_client.launch(engagement_id, authorization_token, roe)
    return {"projectId": r.get("projectId"), "scanId": r.get("scanId"), "status": r.get("status")}


async def list_active_runs() -> dict[str, Any]:
    """List the in-flight scans (status running or pending), newest first.

    Read-only. Use it to see which runs are currently running.

    Returns:
        {"runs": [{"scanId", "projectId", "status", "progress", "startedAt"}, ...]}
    """
    return {"runs": await shor_client.list_active_runs()}


async def get_run_progress(scan_id: str) -> dict[str, Any]:
    """Read-only status of one scan.

    Args:
        scan_id: The scanId returned by start_blackbox_run.

    Returns:
        {"status", "progress", "findingCount", "startedAt", "finishedAt"}
    """
    r = await shor_client.get_scan(scan_id)
    return {
        "status": r.get("status"),
        "progress": r.get("progress"),
        "findingCount": r.get("findingCount"),
        "startedAt": r.get("startedAt"),
        "finishedAt": r.get("finishedAt"),
    }


async def cancel_run(scan_id: str) -> dict[str, Any]:
    """Stop a running scan (the operator kill switch).

    Cancels the run's underlying job execution and marks the scan ``cancelled``.
    Activity-reducing and idempotent: a scan that already finished is returned
    unchanged. Needs no authorization token — stopping a run can never widen
    scope.

    Args:
        scan_id: The scanId returned by start_blackbox_run.

    Returns:
        {"scanId": ..., "status": ...}
    """
    r = await shor_client.cancel_scan(scan_id)
    return {"scanId": r.get("scanId"), "status": r.get("status")}


__all__ = ["start_blackbox_run", "list_active_runs", "get_run_progress", "cancel_run"]
