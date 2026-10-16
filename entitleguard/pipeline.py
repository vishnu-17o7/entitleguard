"""Score every identity. Jev in this pass is the reproducible heuristic."""
from __future__ import annotations

import time

from entitleguard.artifacts import provenance
from entitleguard.artifacts import validate_world
from entitleguard.behavior import fit_behavior
from entitleguard.behavior import peer_prevalence
from entitleguard.drift import drift_report
from entitleguard.fusion import decide
from entitleguard.fusion import necessity
from entitleguard.fusion import severity
from entitleguard.jev import build_state
from entitleguard.jev import consistency_of
from entitleguard.jev import heuristic_judge
from entitleguard.policy import Directory
from entitleguard.simulate import simulate


def _cadence(directory: Directory, identity: dict, permission_id: str) -> str | None:
    for workflow in directory.workflows_for(identity):
        if permission_id in workflow["required_permission_ids"]:
            return str(workflow["cadence"])
    return None


def _proposals(directory: Directory, identity: dict) -> list[dict]:
    proposals = []
    for group_id in identity["group_ids"]:
        group = directory.groups[group_id]
        if group["purpose"] in {"workflow", "peer"}:
            continue
        if group["role_ids"] == [identity["role_id"]]:
            continue
        proposals.append(
            {
                "id": f"group:{group_id}",
                "title": f"Remove group {group['name']}",
                "change": {"type": "remove_group", "group_id": group_id},
            }
        )
    if any(grant["expired"] for grant in identity["temporary_grants"]):
        proposals.append(
            {
                "id": "expired-temporary",
                "title": "Revoke expired temporary admin",
                "change": {"type": "revoke_expired_temporary"},
            }
        )
    for permission_id in identity["extra_permission_ids"]:
        permission = directory.permissions.get(permission_id)
        if permission is None:
            continue
        proposals.append(
            {
                "id": f"perm:{permission_id}",
                "title": f"Remove direct grant {permission['action']}",
                "change": {"type": "remove_direct_grant", "permission_id": permission_id},
            }
        )
    return proposals


def score_permission(
    directory: Directory,
    identity: dict,
    permission_id: str,
    behavior: dict,
    *,
    use_jev: bool,
    use_peers: bool,
    use_context: bool,
    timings: dict | None = None,
) -> dict:
    """Score one effective grant."""
    permission = directory.permissions[permission_id]
    resource = directory.resources[permission["resource_id"]]
    role = directory.roles[identity["role_id"]]
    on_role_document = permission_id in directory.roles[identity["role_id"]]["required_permission_ids"]
    in_workflow = permission_id in directory.workflow_needs(identity)
    in_exception = permission_id in directory.exception_needs(identity)
    in_role = on_role_document and identity["status"] == "active"
    usage = directory.usage_for(identity["id"], permission_id)
    last_used = None if usage is None else int(usage["last_used_days"])
    cadence = _cadence(directory, identity, permission_id)
    state = build_state(
        role_title=role["title"],
        team=identity["team"],
        responsibility=identity["responsibility"],
        action=permission["action"],
        resource_name=resource["name"],
        sensitivity=resource["sensitivity"],
        last_used_days=last_used,
        approved_exception=in_exception,
        in_documented_duties=in_role or in_workflow,
        workflow_cadence=cadence,
    )
    judgment = heuristic_judge(state)
    jev_p = consistency_of(judgment)
    prevalence = peer_prevalence(behavior, identity["role_id"], permission_id)
    probe_started = time.perf_counter()
    probe = simulate(
        directory,
        identity["id"],
        {"type": "remove_permission", "permission_id": permission_id},
    )
    if timings is not None:
        timings["simulation"] += (time.perf_counter() - probe_started) * 1000
    outcome = decide(
        status=identity["status"],
        in_role=in_role,
        in_workflow=in_workflow,
        in_exception=in_exception,
        requirement_class=permission["requirement_class"],
        last_used_days=last_used,
        jev_consistency=jev_p,
        peer_prevalence=prevalence,
        narrowable=directory.narrowable(permission_id, directory.needs(identity) or set(directory.roles[identity["role_id"]]["required_permission_ids"])),
        sim_broken=bool(probe["broken_workflows"]),
        sensitive=resource["sensitivity"] in {"high", "critical"},
        use_jev=use_jev,
        use_peers=use_peers,
        use_context=use_context,
    )
    documented = in_role or in_workflow or in_exception
    return {
        "permission_id": permission_id,
        "action": permission["action"],
        "resource_id": resource["id"],
        "resource_name": resource["name"],
        "sensitivity": resource["sensitivity"],
        "privileged": permission["privileged"],
        "requirement_class": permission["requirement_class"],
        "on_role_document": on_role_document,
        "in_role": in_role,
        "in_workflow": in_workflow,
        "in_exception": in_exception,
        "excess": permission_id not in directory.needs(identity),
        "narrowable": directory.narrowable(
            permission_id,
            directory.needs(identity) or set(directory.roles[identity["role_id"]]["required_permission_ids"]),
        ),
        "last_used_days": last_used,
        "workflow_cadence": cadence,
        "use_count_180d": None if usage is None else usage["use_count_180d"],
        "peer_prevalence": round(prevalence, 4),
        "jev": judgment,
        "necessity": necessity(outcome, jev_p, documented),
        "severity": severity(resource["sensitivity"], permission["privileged"], outcome),
        "outcome": outcome,
        "removal_probe": {
            "safe_to_remove": probe["safe_to_remove"],
            "reason": probe["reason"],
            "broken_workflows": probe["broken_workflows"],
        },
    }


def analyze_world(world: dict) -> dict:
    """Drift, anomaly scores, judgments, and recommendations for the enterprise."""
    validate_world(world)
    directory = Directory(world)
    started = time.perf_counter()
    behavior = fit_behavior(directory)
    fitting_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    timings = {"simulation": 0.0}
    identities: dict[str, dict] = {}
    findings: list[dict] = []
    for identity in world["identities"]:
        granted, sources = directory.effective(identity)
        drift = drift_report(directory, identity)
        rows = [
            score_permission(
                directory,
                identity,
                permission_id,
                behavior,
                use_jev=True,
                use_peers=True,
                use_context=True,
                timings=timings,
            )
            for permission_id in sorted(granted)
        ]
        for row in rows:
            row["sources"] = sources.get(row["permission_id"], [])
        proposals = _proposals(directory, identity)
        for proposal in proposals:
            proposal_started = time.perf_counter()
            proposal["simulation"] = simulate(directory, identity["id"], proposal["change"])
            timings["simulation"] += (time.perf_counter() - proposal_started) * 1000
        record = {
            "id": identity["id"],
            "name": identity["name"],
            "kind": identity["kind"],
            "role_id": identity["role_id"],
            "role_title": directory.roles[identity["role_id"]]["title"],
            "department": identity["department"],
            "team": identity["team"],
            "projects": identity["projects"],
            "status": identity["status"],
            "responsibility": identity["responsibility"],
            "scenarios": identity["scenarios"],
            "split": identity["split"],
            "showcase": identity["showcase"],
            "drift": drift,
            "anomaly": behavior["scores"][identity["id"]],
            "anomaly_flag": behavior["scores"][identity["id"]] >= behavior["threshold"],
            "permissions": rows,
            "proposals": proposals,
        }
        identities[identity["id"]] = record
        for row in rows:
            if row["outcome"] == "retain":
                continue
            findings.append(
                {
                    "identity_id": identity["id"],
                    "name": identity["name"],
                    "role_title": record["role_title"],
                    "permission_id": row["permission_id"],
                    "action": row["action"],
                    "resource_name": row["resource_name"],
                    "outcome": row["outcome"],
                    "severity": row["severity"],
                    "necessity": row["necessity"],
                    "scenario": next(iter(identity["scenarios"]), "unlabeled"),
                }
            )
    findings.sort(key=lambda row: (-row["severity"], row["identity_id"]))
    drift_cases = sum(1 for row in identities.values() if row["drift"]["outside_role"])
    sensitive_paths = sum(
        1
        for record in identities.values()
        for row in record["permissions"]
        if row["excess"] and row["sensitivity"] in {"high", "critical"}
    )
    pending = sum(1 for row in findings if row["outcome"] == "review")
    return {
        "_provenance": provenance(world),
        "timings_ms": {"model_fitting": round(fitting_ms, 3), "simulation": round(timings["simulation"], 3), "scoring_drift_and_assembly": round((time.perf_counter() - started) * 1000 - timings["simulation"], 3)},
        "overview": {
            "identities": len(identities),
            "employees": sum(1 for row in world["identities"] if row["kind"] == "employee"),
            "contractors": sum(row["kind"] == "contractor" for row in world["identities"]),
            "sensitive_excess_grants": sensitive_paths,
            "sensitive_excess_resources": len({row["resource_id"] for record in identities.values() for row in record["permissions"] if row["excess"] and row["sensitivity"] in {"high", "critical"}}),
            "service_accounts": sum(1 for row in world["identities"] if row["kind"] == "service"),
            "drift_cases": drift_cases,
            "sensitive_excess_paths": sensitive_paths,
            "pending_reviews": pending,
            "findings": len(findings),
            "anomaly_threshold": behavior["threshold"],
            "as_of": world["meta"]["as_of"],
        },
        "identities": identities,
        "findings": findings,
        "behavior": {
            "threshold": behavior["threshold"],
            "scores": behavior["scores"],
            "prevalence": behavior["prevalence"],
        },
    }
