"""Fuse policy, simulation, peers, and Jev. Deterministic rules own the outcome."""
from __future__ import annotations


def decide(
    *,
    status: str,
    in_role: bool,
    in_workflow: bool,
    in_exception: bool,
    requirement_class: str,
    last_used_days: int | None,
    jev_consistency: float,
    peer_prevalence: float,
    narrowable: bool,
    sim_broken: bool,
    sensitive: bool,
    use_jev: bool,
    use_peers: bool,
    use_context: bool,
) -> str:
    """Return retain, reduce, temporary, review, or remove.

    Jev can hold an uncertain case for review. It cannot revoke a documented grant
    and it cannot calculate the effective permission.
    """
    if not use_context:
        if last_used_days is None or last_used_days > 90:
            return "remove"
        return "retain"
    if status != "active":
        if last_used_days is None:
            return "review"
        return "remove"
    if in_role or in_workflow:
        return "retain"
    if in_exception:
        return "temporary"
    if requirement_class == "unclassified":
        return "review"
    if requirement_class == "peer_practice":
        if use_peers and peer_prevalence >= 0.8:
            return "review"
        if last_used_days is None:
            return "review"
        return "remove"
    if requirement_class == "contextual":
        if last_used_days is None:
            return "review"
        if use_jev and jev_consistency >= 0.55:
            return "review"
        if sim_broken:
            return "review"
        return "remove"
    if last_used_days is None:
        return "review"
    if narrowable:
        return "reduce"
    if sim_broken:
        return "temporary" if sensitive else "review"
    return "remove"


def necessity(outcome: str, jev_consistency: float, documented: bool) -> float:
    """Heuristic score for documented access necessity. Separate from severity."""
    if documented:
        return round(max(0.84, jev_consistency), 4)
    if outcome == "temporary":
        return 0.64
    if outcome == "review":
        return round(jev_consistency, 4)
    if outcome == "reduce":
        return 0.32
    return round(min(0.18, jev_consistency), 4)


def severity(sensitivity: str, privileged: bool, outcome: str) -> float:
    """Impact of possessing the grant. A necessary critical grant stays severe."""
    base = {"low": 0.15, "medium": 0.35, "high": 0.62, "critical": 0.86}[sensitivity]
    if privileged:
        base += 0.08
    return round(min(base, 1.0), 4)
