"""Automatic policy on the current snapshot.

`run_assessment` is the computational entry point. It never generates a new
enterprise, never calls a hosted model, and never mutates the caller's world.
Safe source removals are applied only to a deep copy, and only after a fresh
counterfactual on that copy.
"""
from __future__ import annotations

import copy
import json
import time
from collections.abc import Callable

from entitleguard.artifacts import POLICY_VERSION
from entitleguard.artifacts import canonical_hash
from entitleguard.artifacts import dataset_hash
from entitleguard.artifacts import provenance
from entitleguard.artifacts import validate_world
from entitleguard.pipeline import analyze_world
from entitleguard.policy import Directory
from entitleguard.simulate import simulate

PHASES: tuple[tuple[str, str], ...] = (
    ("assessment", "Score current evidence"),
    ("policy", "Decide from risk and context"),
    ("simulation", "Test removals on a copy"),
    ("application", "Apply verified removals"),
    ("scoring", "Score the saved copy"),
)

PhaseCallback = Callable[[str, str, int | None, float | None], None]


class AssessmentCancelled(RuntimeError):
    """The caller asked this run to stop before publication."""


def initial_phases() -> list[dict]:
    """Pending phase rows for a run that has not started work."""
    return [{"id": phase_id, "label": label, "status": "pending", "count": None, "elapsed_ms": None} for phase_id, label in PHASES]


def protected_reason(row: dict) -> str | None:
    """Why this grant must stay, or None when a source removal may be attempted.

    Severity and low usage never authorize a removal by themselves. A None
    result still has to survive a cumulative counterfactual before anything
    is edited.
    """
    if row.get("in_workflow"):
        return "A documented workflow requires this permission."
    if row.get("in_role"):
        return "The current role document requires this permission."
    if row.get("in_exception"):
        return "An approved exception covers this permission."
    if row.get("last_used_days") is None:
        return "Usage evidence is missing, so the permission stays."
    if row.get("requirement_class") == "unclassified":
        return "The requirement is unclassified and stays under review."
    outcome = row.get("outcome")
    if outcome == "reduce":
        return "Narrowing is advisory. The permission was not rewritten."
    if outcome == "temporary":
        return "Temporary replacement is advisory. The grant stays until a modeled revocation is verified."
    if outcome == "review":
        probe = row.get("removal_probe") or {}
        return str(probe.get("reason") or "The context is unresolved, so the permission stays.")
    if outcome != "remove":
        return "The policy retained this permission."
    probe = row.get("removal_probe") or {}
    if not probe.get("safe_to_remove"):
        return str(probe.get("reason") or "Removal is not verified safe.")
    return None


def considered(row: dict) -> bool:
    """True when the engine should record a decision for this grant."""
    if row.get("outcome") != "retain":
        return True
    if row.get("excess"):
        return True
    last_used = row.get("last_used_days")
    if last_used is None or last_used > 90:
        return True
    return bool(row.get("severity", 0) >= 0.7 and (row.get("in_workflow") or row.get("in_exception") or row.get("in_role")))


def snapshot_counts(analysis: dict) -> dict:
    """Counts the overview can compare before and after a run."""
    permissions = [row for record in analysis["identities"].values() for row in record["permissions"]]
    overview = analysis["overview"]
    return {
        "effective_grants": len(permissions),
        "findings": overview["findings"],
        "sensitive_excess_grants": overview["sensitive_excess_grants"],
        "sensitive_excess_paths": overview["sensitive_excess_paths"],
        "drift_cases": overview["drift_cases"],
        "pending_reviews": overview["pending_reviews"],
        "remove_recommendations": sum(row["outcome"] == "remove" for row in permissions),
    }


def score_digest(analysis: dict) -> str:
    """Digest of the scores a refresh is allowed to claim it changed."""
    rows = []
    for identity_id, record in sorted(analysis["identities"].items()):
        for row in sorted(record["permissions"], key=lambda item: item["permission_id"]):
            rows.append((identity_id, row["permission_id"], row["outcome"], row["severity"], row["necessity"], record["drift"]["drift"]))
    return canonical_hash(rows)


def _expired(grant: dict, as_of: str) -> bool:
    if grant.get("expires_on"):
        return str(grant["expires_on"]) < as_of
    return bool(grant.get("expired"))


def _risk(record: dict, row: dict) -> dict:
    return {
        "severity": row["severity"],
        "necessity": row["necessity"],
        "outcome": row["outcome"],
        "anomaly": record.get("anomaly"),
        "last_used_days": row.get("last_used_days"),
        "requirement_class": row.get("requirement_class"),
    }


def _compact(result: dict) -> dict:
    return {
        "change": result["change"],
        "verdict": result["verdict"],
        "safe_to_remove": result["safe_to_remove"],
        "reason": result["reason"],
        "removed_permission_ids": result["removed_permission_ids"],
        "broken_workflows": result["broken_workflows"],
        "drops_documented_need": result["drops_documented_need"],
        "missing_usage": result["missing_usage"],
        "workflows": result["workflows"],
        "scope": result["scope"],
    }


def apply_change(world: dict, identity_id: str, change: dict) -> None:
    """Edit one identity assignment on an isolated world copy."""
    identity = next(row for row in world["identities"] if row["id"] == identity_id)
    kind = change["type"]
    if kind == "remove_group":
        identity["group_ids"] = [group_id for group_id in identity["group_ids"] if group_id != change["group_id"]]
    elif kind == "remove_direct_role":
        identity["direct_role_ids"] = [role_id for role_id in identity["direct_role_ids"] if role_id != change["role_id"]]
    elif kind == "remove_direct_grant":
        identity["extra_permission_ids"] = [permission_id for permission_id in identity["extra_permission_ids"] if permission_id != change["permission_id"]]
    elif kind == "revoke_expired_temporary":
        as_of = world["meta"]["as_of"]
        identity["temporary_grants"] = [grant for grant in identity["temporary_grants"] if not _expired(grant, as_of)]
    else:
        raise ValueError(f"unsupported assessment change {kind}")


def _candidates(world: dict, analysis: dict) -> list[dict]:
    directory = Directory(world)
    items: list[dict] = []
    for identity in sorted(world["identities"], key=lambda row: row["id"]):
        record = analysis["identities"][identity["id"]]
        scored = {row["permission_id"]: row for row in record["permissions"]}
        for permission_id in identity["extra_permission_ids"]:
            row = scored.get(permission_id)
            if row is None or protected_reason(row) is not None:
                continue
            items.append({"order": 0, "identity_id": identity["id"], "change": {"type": "remove_direct_grant", "permission_id": permission_id}})
        if any(_expired(grant, world["meta"]["as_of"]) for grant in identity["temporary_grants"]):
            items.append({"order": 1, "identity_id": identity["id"], "change": {"type": "revoke_expired_temporary"}})
        for role_id in identity["direct_role_ids"]:
            items.append({"order": 2, "identity_id": identity["id"], "change": {"type": "remove_direct_role", "role_id": role_id}})
        for group_id in identity["group_ids"]:
            group = directory.groups[group_id]
            if group["purpose"] in {"workflow", "peer"} or group["role_ids"] == [identity["role_id"]]:
                continue
            items.append({"order": 3, "identity_id": identity["id"], "change": {"type": "remove_group", "group_id": group_id}})
    items.sort(key=lambda item: (item["order"], item["identity_id"], json.dumps(item["change"], sort_keys=True)))
    return items


def _block_reason(result: dict, scores: dict[tuple[str, str], dict], identity_id: str) -> str | None:
    if result["broken_workflows"] or result["drops_documented_need"] or result["missing_usage"]:
        return str(result["reason"])
    for permission_id in result["removed_permission_ids"]:
        row = scores.get((identity_id, permission_id))
        if row is None:
            return "A removed permission has no score on this snapshot."
        reason = protected_reason(row)
        if reason:
            return reason
    if result["verdict"] == "blocked":
        return str(result["reason"])
    if result["verdict"] in {"safe", "no_change"}:
        return None
    return str(result["reason"])


def _decision(
    record: dict,
    row: dict,
    *,
    decision: str,
    rationale: str,
    change: dict | None,
    simulation: dict | None,
    simulation_key: str,
    applied_in_simulation: bool,
) -> dict:
    outcome = "safe" if simulation and simulation.get("verdict") == "safe" else "redundant" if simulation and simulation.get("verdict") == "no_change" else "blocked" if simulation else "not_applicable"
    if decision == "hold" and row.get("outcome") in {"reduce", "temporary"}:
        outcome = "unsupported"
    text = rationale if len(rationale) <= 500 else f"{rationale[:497]}..."
    stored_change = change or {"type": "hold", "permission_id": row["permission_id"]}
    return {
        "actor_type": "machine",
        "actor": "EntitleGuard policy",
        "source": "automatic_policy",
        "analyst": "EntitleGuard policy",
        "analyst_is_demo_label": False,
        "kind": "machine",
        "decision": decision,
        "applied": False,
        "applied_in_simulation": applied_in_simulation,
        "rationale": text,
        "identity_id": record["id"],
        "identity_name": record["name"],
        "permission_id": row["permission_id"],
        "policy_version": POLICY_VERSION,
        "rule_version": POLICY_VERSION,
        "risk": _risk(record, row),
        "simulation_outcome": outcome,
        "safe_to_remove": bool(simulation and simulation.get("safe_to_remove")),
        "change": stored_change,
        "simulation": simulation,
        "simulation_key": simulation_key,
    }


def _check(cancel: Callable[[], bool] | None) -> None:
    if cancel is not None and cancel():
        raise AssessmentCancelled("Assessment cancelled")


def run_assessment(
    world: dict,
    *,
    cancel: Callable[[], bool] | None = None,
    on_phase: PhaseCallback | None = None,
    fail_phase: str | None = None,
) -> dict:
    """Score `world`, decide, simulate, and return an isolated final snapshot.

    The returned world is a copy. `world` itself is not modified.
    """
    started = time.perf_counter()
    phases: list[dict] = []
    original = world

    def begin(phase_id: str) -> float:
        _check(cancel)
        if fail_phase == phase_id:
            raise RuntimeError(f"assessment failed during {phase_id}")
        if on_phase is not None:
            on_phase(phase_id, "running", None, None)
        return time.perf_counter()

    def finish(phase_id: str, opened: float, count: int) -> None:
        elapsed = round((time.perf_counter() - opened) * 1000, 3)
        label = dict(PHASES)[phase_id]
        phases.append({"id": phase_id, "label": label, "status": "complete", "count": count, "elapsed_ms": elapsed})
        if on_phase is not None:
            on_phase(phase_id, "complete", count, elapsed)

    opened = begin("assessment")
    initial = analyze_world(original)
    scored = sum(len(record["permissions"]) for record in initial["identities"].values())
    finish("assessment", opened, scored)
    _check(cancel)

    opened = begin("policy")
    scores: dict[tuple[str, str], dict] = {}
    records = initial["identities"]
    for record in records.values():
        for row in record["permissions"]:
            scores[(record["id"], row["permission_id"])] = row
    pending = _candidates(original, initial)
    considered_rows = [(record, row) for record in records.values() for row in record["permissions"] if considered(row)]
    finish("policy", opened, len(considered_rows))
    _check(cancel)

    opened = begin("simulation")
    working = copy.deepcopy(original)
    directory = Directory(working)
    edits: list[dict] = []
    blocked: list[dict] = []
    simulations = 0
    for candidate in pending:
        _check(cancel)
        try:
            result = simulate(directory, candidate["identity_id"], candidate["change"])
        except (KeyError, ValueError):
            continue
        simulations += 1
        reason = _block_reason(result, scores, candidate["identity_id"])
        if reason is not None:
            blocked.append({**candidate, "result": result, "reason": reason})
            continue
        apply_change(working, candidate["identity_id"], candidate["change"])
        edits.append({**candidate, "result": result})
        directory = Directory(working)
    finish("simulation", opened, simulations)
    _check(cancel)

    opened = begin("application")
    validate_world(working)
    removed: dict[str, set[str]] = {}
    for edit in edits:
        if edit["result"]["verdict"] == "safe":
            removed.setdefault(edit["identity_id"], set()).update(edit["result"]["removed_permission_ids"])
    finish("application", opened, len(edits))
    _check(cancel)

    opened = begin("scoring")
    if edits:
        final_world = working
        final_analysis = analyze_world(final_world)
    else:
        final_world = copy.deepcopy(original)
        final_analysis = initial
    final_scored = sum(len(record["permissions"]) for record in final_analysis["identities"].values())
    finish("scoring", opened, final_scored)

    decisions = _assemble_decisions(records, scores, edits, blocked, removed)
    initial_counts = snapshot_counts(initial)
    final_counts = snapshot_counts(final_analysis)
    original_hash = dataset_hash(original)
    final_hash = dataset_hash(final_world)
    world_unchanged = original_hash == final_hash
    unchanged_scores = score_digest(initial) == score_digest(final_analysis)
    note = None
    baseline = None
    if not world_unchanged:
        note = "This snapshot is a remediated copy of the evidence. Benchmark metrics describe the original dataset and are not reported as results for this copy."
        baseline = {
            "status": "unavailable",
            "label": "Original benchmark",
            "dataset_id": provenance(original)["dataset_id"],
            "reason": "Load the baseline snapshot to inspect evaluation metrics for the original dataset.",
        }
    return {
        "final_world": final_world,
        "final_analysis": final_analysis,
        "initial_counts": initial_counts,
        "final_counts": final_counts,
        "scores_unchanged": unchanged_scores,
        "world_unchanged": world_unchanged,
        "decisions": decisions,
        "phases": phases,
        "applied_count": sum(row["decision"] == "apply" for row in decisions),
        "held_count": sum(row["decision"] == "hold" for row in decisions),
        "source_edits": len(edits),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "policy_version": POLICY_VERSION,
        "original_dataset_id": original_hash,
        "final_dataset_id": final_hash,
        "original_label": provenance(original)["dataset_id"],
        "final_label": provenance(final_world)["dataset_id"],
        "evaluation_status": "current" if world_unchanged else "unavailable",
        "evaluation_note": note,
        "baseline_evaluation": baseline,
    }


def _assemble_decisions(
    records: dict[str, dict],
    scores: dict[tuple[str, str], dict],
    edits: list[dict],
    blocked: list[dict],
    removed: dict[str, set[str]],
) -> list[dict]:
    by_permission: dict[tuple[str, str], dict] = {}
    for record in records.values():
        for row in record["permissions"]:
            if not considered(row):
                continue
            reason = protected_reason(row) or "No per-identity source removal could drop this permission without removing protected access."
            by_permission[(record["id"], row["permission_id"])] = _decision(
                record,
                row,
                decision="hold",
                rationale=f"Held. {reason}",
                change=None,
                simulation=None,
                simulation_key=f"hold:{record['id']}:{row['permission_id']}",
                applied_in_simulation=False,
            )
    for item in blocked:
        result = item["result"]
        record = records[item["identity_id"]]
        affected = result["removed_permission_ids"] or [item["change"].get("permission_id")]
        for permission_id in affected:
            if not permission_id:
                continue
            row = scores.get((item["identity_id"], permission_id))
            if row is None or not considered(row):
                continue
            key = (item["identity_id"], permission_id)
            if key in removed.get(item["identity_id"], set()):
                continue
            by_permission[key] = _decision(
                record,
                row,
                decision="hold",
                rationale=f"Held. {item['reason']}",
                change=item["change"],
                simulation=_compact(result),
                simulation_key=f"change:{item['identity_id']}:{json.dumps(item['change'], sort_keys=True)}",
                applied_in_simulation=False,
            )
    for edit in edits:
        result = edit["result"]
        record = records[edit["identity_id"]]
        if result["verdict"] != "safe":
            continue
        for permission_id in result["removed_permission_ids"]:
            row = scores.get((edit["identity_id"], permission_id))
            if row is None:
                continue
            by_permission[(edit["identity_id"], permission_id)] = _decision(
                record,
                row,
                decision="apply",
                rationale=f"Applied in the saved copy. {result['reason']} Severity {row['severity']} did not authorize this by itself; documented need, evidence, and the counterfactual did.",
                change=edit["change"],
                simulation=_compact(result),
                simulation_key=f"change:{edit['identity_id']}:{json.dumps(edit['change'], sort_keys=True)}",
                applied_in_simulation=True,
            )
    return [by_permission[key] for key in sorted(by_permission)]
