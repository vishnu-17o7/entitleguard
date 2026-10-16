"""Run and publish one automatic assessment without blocking the event loop.

`start_assessment` reserves a single in-process job and returns immediately.
`publish_assessment` writes the saved copy, imports decisions, and activates
the snapshot under the run manager's activation lock.
"""
from __future__ import annotations

import copy
import itertools
import threading
import uuid
from datetime import datetime
from datetime import timezone
from typing import Any

from entitleguard.artifacts import atomic_write
from entitleguard.artifacts import compatible
from entitleguard.assess import AssessmentCancelled
from entitleguard.assess import initial_phases
from entitleguard.assess import run_assessment
from entitleguard.job_api import prepare_assessment
from entitleguard.jobs import RunManager


_SEQUENCE = itertools.count(1)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _recency(job: dict[str, Any]) -> tuple:
    return (job.get("created_at") or "", int(job.get("sequence") or 0), job.get("id") or "")


def assessment_view(job: dict[str, Any]) -> dict[str, Any]:
    """Public assessment contract. Paths and process output stay on disk."""
    summary = job.get("summary")
    return {
        "id": job["id"],
        "command": "assess",
        "status": job["status"],
        "idempotency_key": job.get("idempotency_key"),
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "elapsed_ms": job.get("elapsed_ms"),
        "phase": job.get("phase"),
        "phases": job.get("phases") or initial_phases(),
        "summary": summary,
        "error": job.get("error"),
        "activatable": bool(job.get("activatable")),
    }


def latest_assessment(manager: RunManager) -> dict[str, Any]:
    """Return the in-flight assessment and the newest finished one."""
    rows = [job for job in manager.list() if job.get("command") == "assess"]
    active_rows = [job for job in rows if job["status"] in {"queued", "running", "cancelling"}]
    finished = [job for job in rows if job["status"] not in {"queued", "running", "cancelling"}]
    active = assessment_view(max(active_rows, key=_recency)) if active_rows else None
    latest = assessment_view(max(finished, key=_recency)) if finished else None
    return {"active": active, "latest": latest}


def start_assessment(app: Any, idempotency_key: str) -> tuple[dict[str, Any], int]:
    """Start a refresh of the active snapshot, or replay the same key."""
    manager: RunManager = app.state.run_manager
    resources = app.state.resources
    job = {
        "id": uuid.uuid4().hex,
        "command": "assess",
        "seed": resources["world"]["meta"].get("seed"),
        "as_of": resources["world"]["meta"].get("as_of"),
        "status": "queued",
        "created_at": _now(),
        "started_at": None,
        "completed_at": None,
        "exit_code": None,
        "output": "",
        "output_truncated": False,
        "activatable": False,
        "idempotency_key": idempotency_key,
        "sequence": next(_SEQUENCE),
        "phase": None,
        "phases": initial_phases(),
        "summary": None,
        "error": None,
        "elapsed_ms": None,
    }
    stored, created = manager.reserve(job)
    if not created:
        code = 202 if stored["status"] in {"queued", "running", "cancelling"} else 200
        return assessment_view(stored), code
    snapshot = {
        "world": copy.deepcopy(resources["world"]),
        "dataset_id": resources["dataset_id"],
        "epoch": resources.get("epoch", 0),
        "snapshot_version": resources["snapshot_version"],
        "metrics": resources.get("metrics") or {},
        "robustness": resources.get("robustness"),
        "evaluation_status": resources["run"].get("evaluation_status"),
        "evaluation_note": resources["run"].get("evaluation_note"),
        "baseline_evaluation": resources.get("baseline_evaluation"),
        "source_job_id": resources["run"].get("selected_job_id"),
    }
    thread = threading.Thread(target=_worker, args=(app, stored["id"], snapshot), name=f"assess-{stored['id'][:8]}", daemon=True)
    manager.track(thread)
    thread.start()
    return assessment_view(manager.get(stored["id"])), 202


def _worker(app: Any, job_id: str, snapshot: dict[str, Any]) -> None:
    manager: RunManager = app.state.run_manager
    if not manager.claim_running(job_id):
        return

    def cancelled() -> bool:
        return manager.get(job_id)["status"] in {"cancelling", "cancelled"}

    def on_phase(phase_id: str, status: str, count: int | None, elapsed_ms: float | None) -> None:
        current = manager.get(job_id)
        phases = [dict(row) for row in current.get("phases") or initial_phases()]
        for row in phases:
            if row["id"] == phase_id:
                row["status"] = status
                if count is not None:
                    row["count"] = count
                if elapsed_ms is not None:
                    row["elapsed_ms"] = elapsed_ms
        line = f"{phase_id} {status}" if count is None else f"{phase_id} {status} {count}"
        output = f"{current.get('output') or ''}{line}\n"
        manager.update_job(job_id, phase=phase_id, phases=phases, output=output[-65536:])
        blocker = getattr(app.state, "assessment_block", None)
        if blocker is not None and phase_id == "assessment" and status == "running":
            blocker.wait(timeout=15)

    try:
        result = run_assessment(
            snapshot["world"],
            cancel=cancelled,
            on_phase=on_phase,
            fail_phase=getattr(app.state, "assessment_fail", None),
        )
        if cancelled():
            raise AssessmentCancelled("Assessment cancelled")
        _publish(app, job_id, snapshot, result)
    except AssessmentCancelled:
        manager.update_job(job_id, status="cancelled", completed_at=_now(), activatable=False, error=None)
    except Exception as exc:
        message = str(exc) or exc.__class__.__name__
        status = "stale" if message.startswith("stale assessment") else "failed"
        manager.update_job(job_id, status=status, completed_at=_now(), activatable=False, error=message)


def _publish(app: Any, job_id: str, snapshot: dict[str, Any], result: dict[str, Any]) -> None:
    from api import initialize

    manager: RunManager = app.state.run_manager
    with manager.activation_lock:
        current = app.state.resources
        if current["dataset_id"] != snapshot["dataset_id"] or current.get("epoch", 0) != snapshot["epoch"]:
            raise RuntimeError("stale assessment: the active snapshot changed before publication")
        if manager.get(job_id)["status"] in {"cancelling", "cancelled"}:
            raise AssessmentCancelled("Assessment cancelled")
        metrics_ok = bool(snapshot.get("metrics")) and compatible(snapshot["metrics"], result["final_world"])
        inherited = snapshot.get("evaluation_status") == "unavailable" or snapshot.get("evaluation_note") or snapshot.get("baseline_evaluation")
        if result["world_unchanged"] and not metrics_ok and inherited:
            result["evaluation_status"] = "unavailable"
            result["evaluation_note"] = snapshot.get("evaluation_note")
            result["baseline_evaluation"] = snapshot.get("baseline_evaluation")
        directory = manager.root / job_id
        decisions = _materialize(result, job_id, snapshot["snapshot_version"])
        summary = _summary(result, job_id, snapshot.get("source_job_id"))
        summary["idempotency_key"] = manager.get(job_id).get("idempotency_key")
        atomic_write(directory / "data" / "enterprise.json", result["final_world"])
        atomic_write(directory / "data" / "analysis.json", result["final_analysis"])
        atomic_write(directory / "results" / "assessment.json", {**summary, "status": "succeeded", "phases": result["phases"]})
        atomic_write(directory / "results" / "decisions.json", {"decisions": decisions})
        if result["world_unchanged"] and snapshot.get("metrics") and compatible(snapshot["metrics"], result["final_world"]):
            atomic_write(directory / "results" / "metrics.json", snapshot["metrics"])
        if result["world_unchanged"] and snapshot.get("robustness"):
            atomic_write(directory / "results" / "robustness.json", snapshot["robustness"])
        previous = None
        try:
            previous = manager.selected()
        except (KeyError, OSError, ValueError, TypeError):
            previous = None
        manager.update_job(
            job_id,
            status="succeeded",
            activatable=True,
            completed_at=_now(),
            elapsed_ms=result["elapsed_ms"],
            summary=summary,
            phases=result["phases"],
            error=None,
            phase="scoring",
        )
        try:
            manager.select(job_id)
            state = prepare_assessment(directory, current["store"].path, initialize)
            state["epoch"] = snapshot["epoch"] + 1
            state["run"]["selected_job_id"] = job_id
            state["assessment"] = summary
            app.state.resources = state
        except Exception:
            app.state.resources = current
            try:
                manager.select(previous)
            except (KeyError, OSError, ValueError, TypeError):
                pass
            manager.update_job(job_id, force=True, status="failed", activatable=False, completed_at=_now(), error="publication failed")
            raise


def _summary(result: dict[str, Any], run_id: str, source_job_id: str | None) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "scores_unchanged": result["scores_unchanged"],
        "world_unchanged": result["world_unchanged"],
        "applied_count": result["applied_count"],
        "held_count": result["held_count"],
        "source_edits": result["source_edits"],
        "decision_counts": {"apply": result["applied_count"], "hold": result["held_count"]},
        "initial_counts": result["initial_counts"],
        "final_counts": result["final_counts"],
        "original_dataset_id": result["original_dataset_id"],
        "final_dataset_id": result["final_dataset_id"],
        "original_dataset_label": result["original_label"],
        "final_dataset_label": result["final_label"],
        "policy_version": result["policy_version"],
        "evaluation_status": result["evaluation_status"],
        "evaluation_note": result["evaluation_note"],
        "baseline_evaluation": result["baseline_evaluation"],
        "source_job_id": source_job_id,
        "elapsed_ms": result["elapsed_ms"],
    }


def _materialize(result: dict[str, Any], run_id: str, snapshot_version: str) -> list[dict]:
    created = _now()
    simulations: dict[str, str] = {}
    rows = []
    for decision in result["decisions"]:
        key = decision["simulation_key"]
        if key not in simulations:
            simulations[key] = str(uuid.uuid4())
        simulation_id = simulations[key]
        compact = decision.get("simulation") or {
            "change": decision["change"],
            "verdict": "blocked" if decision["decision"] == "hold" else "safe",
            "safe_to_remove": decision["safe_to_remove"],
            "reason": decision["rationale"],
            "removed_permission_ids": [],
            "broken_workflows": [],
            "drops_documented_need": False,
            "missing_usage": False,
            "workflows": [],
            "scope": "specific_source",
        }
        record = {
            **compact,
            "simulation_id": simulation_id,
            "dataset_id": result["original_dataset_id"],
            "identity_id": decision["identity_id"],
            "snapshot_version": snapshot_version,
            "created_at": created,
        }
        rows.append({
            **decision,
            "id": str(uuid.uuid4()),
            "simulation_id": simulation_id,
            "simulation": compact,
            "simulation_record": record,
            "dataset_id": result["final_dataset_id"],
            "original_dataset_id": result["original_dataset_id"],
            "final_dataset_id": result["final_dataset_id"],
            "run_id": run_id,
            "idempotency_key": f"machine:{run_id}:{decision['identity_id']}:{decision['permission_id']}",
            "created_at": created,
            "snapshot_version": snapshot_version,
        })
    return rows
