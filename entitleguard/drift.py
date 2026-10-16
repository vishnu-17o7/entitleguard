"""Temporal privilege drift. Unknown grants stay marked uncertain."""
from __future__ import annotations

from entitleguard.policy import Directory


def drift_ratio(granted: set[str], needed: set[str]) -> float:
    """D = |G \\ N| / max(1, |G|)."""
    if not granted:
        return 0.0
    return len(granted - needed) / max(1, len(granted))


def _clone_at(identity: dict, point: dict) -> dict:
    return {
        **identity,
        "_as_of": point["date"],
        "role_id": point["role_id"],
        "group_ids": list(point["group_ids"]),
        "direct_role_ids": list(point.get("direct_role_ids", [])),
        "extra_permission_ids": list(point.get("extra_permission_ids", [])),
        "deny_permission_ids": list(point.get("deny_permission_ids", [])),
        "temporary_grants": list(point.get("temporary_grants", [])),
        "status": point.get("status", "active"),
    }


def drift_report(directory: Directory, identity: dict) -> dict:
    """Current drift plus a timeline from role history."""
    granted, _sources = directory.effective(identity)
    needed = directory.needs(identity)
    excess = sorted(granted - needed)
    outside_role: list[str] = []
    uncertain: list[str] = []
    other: list[str] = []
    for permission_id in excess:
        kind = directory.permissions[permission_id]["requirement_class"]
        if kind == "catalogued":
            outside_role.append(permission_id)
        elif kind == "unclassified":
            uncertain.append(permission_id)
        else:
            other.append(permission_id)
    timeline = []
    for point in identity["role_history"]:
        past = _clone_at(identity, point)
        past_granted, _sources = directory.effective(past)
        past_needed = directory.needs(past)
        timeline.append(
            {
                "reconstructed": True,
                "date": point["date"],
                "role_id": point["role_id"],
                "role_title": directory.roles[point["role_id"]]["title"],
                "granted": len(past_granted),
                "needed": len(past_needed),
                "drift": round(drift_ratio(past_granted, past_needed), 4),
            }
        )
    return {
        "granted": len(granted),
        "needed": len(needed),
        "drift": round(drift_ratio(granted, needed), 4),
        "outside_role": outside_role,
        "uncertain": uncertain,
        "other": other,
        "timeline": timeline,
    }
