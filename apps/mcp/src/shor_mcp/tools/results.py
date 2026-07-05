"""Result-reading tools: findings, report, attack-surface, and the guest link.

All read-only with respect to scanning. ``get_share_url`` is the one client-facing
output; the other three let the model reason over what a scan actually found
instead of only its finding count.
"""

from __future__ import annotations

from typing import Any

from .. import shor_client


async def get_findings(scan_id: str) -> dict[str, Any]:
    """Read a scan's finding records.

    Args:
        scan_id: The scanId returned by start_blackbox_run.

    Returns:
        {"findings": [ {finding record}, ... ]}
    """
    return {"findings": await shor_client.get_findings(scan_id)}


async def get_report(scan_id: str) -> dict[str, Any]:
    """Read a scan's finalized executive report.

    Returns ``{"report": null}`` (not an error) while the scan exists but its
    report has not been finalized yet.

    Args:
        scan_id: The scanId returned by start_blackbox_run.

    Returns:
        {"report": <report object> | None}
    """
    return {"report": await shor_client.get_report(scan_id)}


async def get_attack_surface(scan_id: str) -> dict[str, Any]:
    """Read a scan's attack-surface document (scenarios + kill chains).

    Returns an empty document while synthesis has not landed yet.

    Args:
        scan_id: The scanId returned by start_blackbox_run.

    Returns:
        {"attackSurface": {"scenarios": [...], ...}}
    """
    return {"attackSurface": await shor_client.get_attack_surface(scan_id)}


async def get_share_url(project_id: str) -> dict[str, Any]:
    """Mint (or read) the project's read-only guest link — the only client-facing
    output of a run. Read-only with respect to scanning.

    Args:
        project_id: The projectId returned by start_blackbox_run.

    Returns:
        {"shareUrl": ...}
    """
    r = await shor_client.share(project_id)
    return {"shareUrl": r.get("shareUrl")}


__all__ = ["get_findings", "get_report", "get_attack_surface", "get_share_url"]
