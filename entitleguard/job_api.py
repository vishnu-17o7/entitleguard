from __future__ import annotations

from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Literal

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from config import AS_OF
from config import SEED
from entitleguard.artifacts import canonical_hash
from entitleguard.artifacts import compatible
from entitleguard.artifacts import compatible_robustness
from entitleguard.artifacts import load_robustness
from entitleguard.artifacts import read_json
from entitleguard.artifacts import validate_world
from entitleguard.generate import generate_enterprise
from entitleguard.jobs import RunManager


class ExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: Literal["all", "benchmark"] = "all"
    seed: int = Field(default=SEED, ge=0, le=2**31 - 1, strict=True)
    as_of: date = date.fromisoformat(AS_OF)


class ActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str | None = Field(default=None, min_length=1, max_length=100)


def prepare_completed(
    directory: Path,
    ledger_path: Path,
    initialize: Callable[..., dict],
) -> dict:
    """Validate a complete immutable run before replacing application state."""
    world = read_json(directory / "data" / "enterprise.json")
    analysis = read_json(directory / "data" / "analysis.json")
    metrics = read_json(directory / "results" / "metrics.json")
    manifest = read_json(directory / "results" / "manifest.json")
    if any(value is None for value in (world, analysis, metrics, manifest)):
        raise ValueError("This run is missing a complete dataset, analysis, metrics, or manifest.")
    validate_world(world)
    if not compatible(analysis, world) or not compatible(metrics, world):
        raise ValueError("This run was produced by a different version. Run the experiment again.")
    if manifest.get("status") != "completed" or manifest.get("analysis_hash") != canonical_hash(analysis) or manifest.get("metrics_hash") != canonical_hash(metrics):
        raise ValueError("The completed run manifest does not match its artifacts.")
    state = initialize(world, analysis, metrics, ledger_path)
    state["robustness"] = load_robustness(world, directory / "results")
    return state


def prepare_assessment(
    directory: Path,
    ledger_path: Path,
    initialize: Callable[..., dict],
) -> dict:
    """Load a remediated snapshot. Old benchmark metrics are not reused for a changed world."""
    from entitleguard.artifacts import compatible
    from entitleguard.artifacts import load_robustness
    from entitleguard.storage import Ledger

    world = read_json(directory / "data" / "enterprise.json")
    analysis = read_json(directory / "data" / "analysis.json")
    manifest = read_json(directory / "results" / "assessment.json")
    saved = read_json(directory / "results" / "decisions.json")
    if any(value is None for value in (world, analysis, manifest, saved)):
        raise ValueError("This assessment is missing its saved snapshot or decisions.")
    if manifest.get("status") != "succeeded":
        raise ValueError("This assessment did not finish.")
    validate_world(world)
    if not compatible(analysis, world):
        raise ValueError("This assessment was produced by a different version. Run it again.")
    metrics = read_json(directory / "results" / "metrics.json") if manifest.get("world_unchanged") else None
    if metrics is not None and not compatible(metrics, world):
        metrics = None
    state = initialize(world, analysis, metrics if metrics else {}, ledger_path)
    if manifest.get("world_unchanged") and metrics:
        state["metrics"] = metrics
        state["robustness"] = load_robustness(world, directory / "results")
        state["run"]["evaluation_status"] = "current"
        state["run"]["evaluation_note"] = None
        state["baseline_evaluation"] = None
    else:
        state["metrics"] = {}
        state["robustness"] = None
        status = manifest.get("evaluation_status")
        if status not in {"current", "unavailable"}:
            status = "current" if manifest.get("world_unchanged") else "unavailable"
        if status == "current":
            status = "unavailable"
        state["run"]["evaluation_status"] = status
        state["run"]["evaluation_note"] = manifest.get("evaluation_note")
        state["baseline_evaluation"] = manifest.get("baseline_evaluation")
    state["run"]["assessment_id"] = manifest.get("run_id")
    state["run"]["derived"] = state["run"].get("evaluation_status") == "unavailable" or not manifest.get("world_unchanged")
    state["assessment"] = {key: value for key, value in manifest.items() if key not in {"phases"}}
    Ledger(ledger_path).import_assessment(
        {"id": manifest["run_id"], "idempotency_key": manifest.get("idempotency_key"), "status": "succeeded", **state["assessment"]},
        saved["decisions"],
    )
    return state


def restore_selection(
    manager: RunManager,
    baseline: dict,
    initialize: Callable[..., dict],
) -> dict:
    """Restore the last verified run, falling back visibly to the baseline."""
    try:
        selected = manager.selected()
        if selected is not None:
            directory = manager.completed_directory(selected)
            job = manager.get(selected)
            if job.get("command") == "assess":
                state = prepare_assessment(directory, baseline["store"].path, initialize)
            else:
                state = prepare_completed(directory, baseline["store"].path, initialize)
            state["run"]["selected_job_id"] = selected
            state["epoch"] = 0
            return state
    except (KeyError, OSError, ValueError, TypeError) as exc:
        baseline["run"]["restore_warning"] = f"Previous experiment unavailable: {exc}"
    baseline["run"]["selected_job_id"] = None
    baseline["epoch"] = 0
    return baseline


def build_job_router(initialize: Callable[..., dict], baseline_loader: Callable[[], dict]) -> APIRouter:
    """Expose bounded local experiments and atomic active-run selection."""
    router = APIRouter(prefix="/api", tags=["experiments"])

    @router.get("/jobs", response_class=JSONResponse)
    async def list_jobs(request: Request) -> dict:
        return {"items": await run_in_threadpool(request.app.state.run_manager.list), "selected_job_id": request.app.state.resources["run"].get("selected_job_id")}

    @router.post("/jobs", response_class=JSONResponse, status_code=202)
    async def start_job(body: ExperimentRequest, request: Request) -> dict:
        try:
            return await run_in_threadpool(request.app.state.run_manager.start, body.command, body.seed, body.as_of.isoformat())
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/jobs/{job_id}", response_class=JSONResponse)
    async def get_job(job_id: str, request: Request) -> dict:
        try:
            return await run_in_threadpool(request.app.state.run_manager.get, job_id)
        except KeyError as exc:
            raise HTTPException(404, "Experiment not found") from exc

    @router.post("/jobs/{job_id}/cancel", response_class=JSONResponse)
    async def cancel_job(job_id: str, request: Request) -> dict:
        try:
            return await run_in_threadpool(request.app.state.run_manager.cancel, job_id)
        except KeyError as exc:
            raise HTTPException(404, "Experiment not found") from exc

    @router.get("/jobs/{job_id}/results", response_class=JSONResponse)
    async def job_results(job_id: str, request: Request) -> dict:
        def read_results() -> dict:
            manager = request.app.state.run_manager
            job = manager.get(job_id)
            if job["status"] != "succeeded":
                raise ValueError("Results are available only after a successful experiment.")
            directory = manager.root / job_id
            if job["command"] == "benchmark":
                payload = read_json(directory / "results" / "robustness.json")
                world = generate_enterprise(job["seed"], job["as_of"])
                if payload is None or not compatible_robustness(payload, world):
                    raise ValueError("This benchmark is missing or stale. Run it again.")
                return {"job_id": job_id, "command": "benchmark", "robustness": payload}
            state = prepare_completed(directory, request.app.state.resources["store"].path, initialize)
            return {"job_id": job_id, "command": "all", "metrics": state["metrics"], "run": state["run"]}
        try:
            return await run_in_threadpool(read_results)
        except KeyError as exc:
            raise HTTPException(404, "Experiment not found") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.post("/run/activate", response_class=JSONResponse)
    async def activate(body: ActivateRequest, request: Request) -> dict:
        def switch() -> dict:
            manager = request.app.state.run_manager
            with manager.activation_lock:
                current = request.app.state.resources
                if body.job_id is None:
                    next_state = baseline_loader()
                else:
                    directory = manager.completed_directory(body.job_id)
                    job = manager.get(body.job_id)
                    if job.get("command") == "assess":
                        next_state = prepare_assessment(directory, current["store"].path, initialize)
                    else:
                        next_state = prepare_completed(directory, current["store"].path, initialize)
                manager.select(body.job_id)
                next_state["run"]["selected_job_id"] = body.job_id
                next_state["epoch"] = current.get("epoch", 0) + 1
                request.app.state.resources = next_state
                return {"dataset_id": next_state["dataset_id"], "run": next_state["run"], "selected_job_id": body.job_id}
        try:
            return await run_in_threadpool(switch)
        except KeyError as exc:
            raise HTTPException(404, "Experiment not found") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(409, str(exc)) from exc

    return router
