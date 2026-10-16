"""EntitleGuard's local, offline-first investigation API."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from typing import Any
from typing import Literal
from typing import Union

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import APIRouter
from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from config import DB_PATH
from entitleguard.assessment_run import assessment_view
from entitleguard.assessment_run import latest_assessment
from entitleguard.assessment_run import start_assessment
from entitleguard.catalogue import _catalog
from entitleguard.graph import graph_payload
from entitleguard.jev import JevClient
from entitleguard.jev import build_state
from entitleguard.job_api import build_job_router
from entitleguard.job_api import restore_selection
from entitleguard.jobs import RunManager
from entitleguard.policy import Directory
from entitleguard.simulate import simulate
from entitleguard.storage import Ledger

WEB = ROOT / "web"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class GroupChange(StrictModel):
    type: Literal["remove_group"]
    group_id: str = Field(min_length=1, max_length=100)


class RoleChange(StrictModel):
    type: Literal["remove_direct_role"]
    role_id: str = Field(min_length=1, max_length=100)


class PermissionChange(StrictModel):
    type: Literal["remove_permission", "remove_direct_grant"]
    permission_id: str = Field(min_length=1, max_length=100)


class ExpiredChange(StrictModel):
    type: Literal["revoke_expired_temporary"]


class SimulateRequest(StrictModel):
    identity_id: str = Field(min_length=1, max_length=100)
    change: Annotated[Union[GroupChange, RoleChange, PermissionChange, ExpiredChange], Field(discriminator="type")]


class DecisionRequest(StrictModel):
    simulation_id: str = Field(min_length=1, max_length=100)
    decision: Literal["accept", "reject", "defer"]
    analyst: str = Field(min_length=2, max_length=100)
    rationale: str = Field(min_length=8, max_length=3000)
    idempotency_key: str = Field(min_length=8, max_length=100)


class JevRequest(StrictModel):
    permission_id: str = Field(min_length=1, max_length=100)


class AssessmentRequest(StrictModel):
    idempotency_key: str = Field(min_length=8, max_length=100)


class Page(BaseModel):
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int
    model_config = ConfigDict(extra="allow")


def resources(request: Request) -> dict:
    """Return the active snapshot after any in-flight publication finishes.

    A refresh marks its job succeeded before the snapshot swap. Waiting on the
    activation lock keeps readers from observing that half-published state.
    """
    manager = getattr(request.app.state, "run_manager", None)
    if manager is None:
        return request.app.state.resources
    with manager.activation_lock:
        return request.app.state.resources


State = Annotated[dict, Depends(resources)]


def record(state: dict, identity_id: str) -> dict:
    found = state["analysis"]["identities"].get(identity_id)
    if found is None:
        raise HTTPException(404, detail={"code": "unknown_identity", "message": "Unknown identity"})
    return found


def page(rows: list[dict], q: str, limit: int, offset: int) -> dict:
    needle = q.casefold().strip()
    filtered = [row for row in rows if not needle or needle in json.dumps(row, ensure_ascii=False).casefold()]
    return {"items": filtered[offset:offset + limit], "total": len(filtered), "limit": limit, "offset": offset}


def _benchmark_reference(state: dict) -> dict:
    """Identify the pre-remediation dataset without treating its score as the copy's score."""
    assessment = state.get("assessment") or {}
    baseline = assessment.get("baseline_evaluation") or state.get("baseline_evaluation") or {}
    return {"dataset_hash": baseline.get("dataset_hash"), "dataset_id": baseline.get("dataset_id"), "original_dataset_id": assessment.get("original_dataset_id")}


def _benchmark_notice(state: dict) -> str:
    """Explain that an export of the saved benchmark is not a new result for the copy."""
    assessment = state.get("assessment") or {}
    initial = assessment.get("initial_counts") or {}
    final = assessment.get("final_counts") or {}
    overview = (state.get("analysis") or {}).get("overview") or {}
    notice = "These figures are the original benchmark. They describe the dataset before remediation and are not a new accuracy result for the active copy."
    if "sensitive_excess_grants" in initial and "sensitive_excess_grants" in final and initial["sensitive_excess_grants"] != final["sensitive_excess_grants"]:
        notice += f" The refresh that created this copy moved sensitive excess grants from {initial['sensitive_excess_grants']} to {final['sensitive_excess_grants']}, with {assessment.get('applied_count', 0)} verified removals and {assessment.get('held_count', 0)} holds."
    elif "sensitive_excess_grants" in overview:
        notice += f" The active snapshot currently has {overview.get('findings')} findings and {overview['sensitive_excess_grants']} sensitive excess grants."
    return notice


def initialize(world: dict | None, analysis: dict | None, metrics: dict | None, db_path: Path) -> dict:
    from run import load_analysis
    from run import load_world
    from entitleguard.artifacts import dataset_hash
    from entitleguard.artifacts import load_metrics
    from entitleguard.artifacts import load_robustness
    from entitleguard.artifacts import run_metadata

    world = world if world is not None else load_world()
    analysis = analysis if analysis is not None else load_analysis()
    if metrics is None:
        metrics = load_metrics(world, analysis)
    return {"world": world, "analysis": analysis, "metrics": metrics or {}, "directory": Directory(world),
            "dataset_id": dataset_hash(world), "snapshot_version": hashlib.sha256(json.dumps([dataset_hash(world), analysis.get("_provenance", {})], sort_keys=True).encode()).hexdigest(), "run": run_metadata(world, analysis), "store": Ledger(db_path),
            "jev_cache": {}, "jev_lock": asyncio.Lock(), "robustness": load_robustness(world)}


def create_app(*, world: dict | None = None, analysis: dict | None = None, metrics: dict | None = None, db_path: Path | str = DB_PATH) -> FastAPI:
    """Create isolated resources; tests supply a temporary ledger and dataset."""
    def baseline_loader() -> dict:
        return initialize(world, analysis, metrics, Path(db_path))

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        baseline = await run_in_threadpool(baseline_loader)
        manager = await run_in_threadpool(RunManager, ROOT, Path(db_path).parent)
        application.state.run_manager = manager
        application.state.resources = await run_in_threadpool(restore_selection, manager, baseline, initialize)
        application.state.resources.setdefault("epoch", 0)
        try:
            yield
        finally:
            await run_in_threadpool(manager.close)
            application.state.resources = None

    application = FastAPI(title="EntitleGuard", lifespan=lifespan)
    application.mount("/static", StaticFiles(directory=WEB), name="static")

    @application.middleware("http")
    async def local_mutations(request: Request, call_next: Any) -> Response:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            from urllib.parse import urlsplit
            origin = request.headers.get("origin")
            host = request.headers.get("host", "").split(":")[0]
            if host not in {"127.0.0.1", "localhost", "testserver"} or (origin and urlsplit(origin).netloc != request.headers.get("host")):
                return JSONResponse({"detail": {"code": "invalid_origin", "message": "Local same-origin requests required"}}, status_code=403)
        return await call_next(request)

    @application.get("/", response_class=FileResponse)
    async def index() -> FileResponse:
        return FileResponse(WEB / "index.html")

    router = APIRouter(prefix="/api", tags=["investigations"])

    @router.get("/health", response_class=JSONResponse)
    async def health(state: State) -> dict:
        return {"status": "ready", "dataset_id": state["dataset_id"], "offline_demo": True}

    @router.get("/run", response_class=JSONResponse)
    async def current_run(state: State) -> dict:
        from config import jev_provider
        return {**state["run"], "dataset_id": state["dataset_id"], "provider": jev_provider(), "features": {"decisions_applied": False, "source_simulation": True, "automatic_assessment": True, "simulated_removals": True}}

    @router.get("/overview", response_class=JSONResponse)
    async def overview(state: State, request: Request) -> dict:
        assessment = await run_in_threadpool(latest_assessment, request.app.state.run_manager)
        return {"overview": state["analysis"]["overview"], "findings": state["analysis"]["findings"][:30],
                "metrics": state["metrics"] if state["run"].get("evaluation_status") != "unavailable" else {},
                "run": state["run"], "dataset_id": state["dataset_id"], "assessment": assessment, "demos": [
                    {"id": "EMP-104", "title": "Role transfer", "text": "Maya's former group still grants warehouse access."},
                    {"id": "EMP-027", "title": "Quarterly recovery", "text": "Arun's recovery duty explains rare usage."},
                    {"id": "SVC-018", "title": "Service account", "text": "Preserve landing-bucket duties; inspect unrelated credentials."}]}

    @router.get("/identities", response_class=JSONResponse, response_model=Page)
    async def identities(state: State, q: str = Query("", max_length=200), kind: Literal["", "employee", "contractor", "service"] = "", department: str = Query("", max_length=100), outcome: Literal["", "retain", "remove", "review", "temporary", "reduce"] = "", limit: int = Query(40, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
        rows = []
        for row in state["analysis"]["identities"].values():
            identity = state["directory"].identity(row["id"])
            if kind and identity["kind"] != kind or department and row["department"] != department:
                continue
            if outcome and not any(p["outcome"] == outcome for p in row["permissions"]):
                continue
            rows.append({key: row.get(key) for key in ("id", "name", "role_title", "team", "status", "showcase", "anomaly", "department")} | {"kind": identity["kind"], "drift": row["drift"]["drift"],
                "remove_count": sum(p["outcome"] == "remove" for p in row["permissions"]), "retain_count": sum(p["outcome"] == "retain" for p in row["permissions"]), "other_count": sum(p["outcome"] not in {"retain", "remove"} for p in row["permissions"])})
        rows.sort(key=lambda row: (row["showcase"] is None, row["id"]))
        result = page(rows, q, limit, offset)
        return {**result, "identities": result["items"]}

    @router.get("/findings", response_class=JSONResponse, response_model=Page)
    async def findings(state: State, q: str = Query("", max_length=200), kind: Literal["", "employee", "contractor", "service"] = "", department: str = Query("", max_length=100), outcome: Literal["", "retain", "remove", "review", "temporary", "reduce"] = "", severity: str = Query("", max_length=20), sort: Literal["severity", "name"] = "severity", evidence: Literal["", "missing", "complete"] = "", review_status: Literal["", "recorded", "unrecorded"] = "", limit: int = Query(40, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
        exact_severity: float | None = None
        if severity and severity not in {"high", "medium", "low"}:
            try:
                exact_severity = float(severity)
                if not 0 <= exact_severity <= 1:
                    raise ValueError("Severity outside [0,1]")
            except ValueError as exc:
                raise HTTPException(422, "Severity must be high, medium, low, or a number in [0,1]") from exc
        recorded: set[tuple[str, str]] = set()
        ledger = await run_in_threadpool(state["store"].decisions)
        for decision in ledger:
            if decision["dataset_id"] != state["dataset_id"]:
                continue
            proposal = decision["change"]
            simulation = decision.get("simulation", {})
            affected = set(simulation.get("removed_permission_ids", []))
            if proposal.get("permission_id"):
                affected.add(proposal["permission_id"])
            for permission_id, sources in simulation.get("sources_before", {}).items():
                for source in sources:
                    if proposal["type"] == "remove_group" and source.get("group_id") == proposal.get("group_id") or proposal["type"] == "remove_direct_role" and source.get("type") == "role" and source.get("role_id") == proposal.get("role_id") or proposal["type"] == "revoke_expired_temporary" and source.get("type") == "temporary" and source.get("expired") == "yes":
                        affected.add(permission_id)
            recorded.update((decision["identity_id"], permission_id) for permission_id in affected)
        rows = []
        for row in state["analysis"]["findings"]:
            identity = state["directory"].identity(row["identity_id"])
            score = float(row["severity"])
            severity_band = "high" if score >= 0.7 else "medium" if score >= 0.4 else "low"
            complete = state["directory"].usage_for(identity["id"], row["permission_id"]) is not None
            reviewed = (identity["id"], row["permission_id"]) in recorded
            status = "recorded" if reviewed else "unrecorded"
            if kind and identity["kind"] != kind or department and identity["department"] != department or outcome and row["outcome"] != outcome:
                continue
            if severity and (exact_severity is not None and score != exact_severity or exact_severity is None and severity_band != severity):
                continue
            if evidence and evidence != ("complete" if complete else "missing") or review_status and review_status != status:
                continue
            rows.append({**row, "kind": identity["kind"], "department": identity["department"], "severity_band": severity_band, "evidence_complete": complete, "review_status": status})
        rows.sort(key=(lambda row: (-float(row["severity"]), row["identity_id"], row["permission_id"])) if sort == "severity" else (lambda row: (row["name"].casefold(), row["identity_id"], row["permission_id"])))
        return page(rows, q, limit, offset)

    @router.get("/catalog", response_class=JSONResponse)
    async def catalog(state: State, collection: str | None = None, q: str = Query("", max_length=200), limit: int = Query(40, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
        catalog = await run_in_threadpool(_catalog, state)
        if collection is None:
            return catalog
        if collection not in catalog or collection == "counts":
            raise HTTPException(422, "Unknown collection")
        return {**page(catalog[collection], q, limit, offset), "counts": catalog["counts"], "collection": collection}

    @router.get("/identities/{identity_id}", response_class=JSONResponse)
    async def detail(identity_id: str, state: State) -> dict:
        return {"identity": record(state, identity_id), "activity": [r for r in state["world"]["activity"] if r["identity_id"] == identity_id], "dataset_id": state["dataset_id"]}

    @router.get("/identities/{identity_id}/graph", response_class=JSONResponse)
    async def graph(identity_id: str, state: State) -> dict:
        record(state, identity_id)
        return await run_in_threadpool(graph_payload, state["directory"], state["directory"].identity(identity_id))

    @router.post("/identities/{identity_id}/jev", response_class=JSONResponse)
    async def judgment(identity_id: str, body: JevRequest, state: State) -> dict:
        identity = record(state, identity_id)
        row = next((p for p in identity["permissions"] if p["permission_id"] == body.permission_id), None)
        if row is None:
            raise HTTPException(404, "Permission is not effective for this identity")
        context = build_state(role_title=identity["role_title"], team=identity["team"], responsibility=identity["responsibility"], action=row["action"], resource_name=row["resource_name"], sensitivity=row["sensitivity"], last_used_days=row["last_used_days"], approved_exception=bool(row["in_exception"]), in_documented_duties=bool(row["in_role"] or row["in_workflow"]), workflow_cadence=row.get("workflow_cadence"))
        from config import JEV_SCHEMA_VERSION
        from config import JEV_OPENROUTER_MODEL
        from config import JEV_TYPESAFE_MODEL
        from config import jev_provider
        import time
        key = hashlib.sha256(json.dumps([state["snapshot_version"], context, JEV_SCHEMA_VERSION, jev_provider(), JEV_OPENROUTER_MODEL, JEV_TYPESAFE_MODEL], sort_keys=True).encode()).hexdigest()
        async with state["jev_lock"]:
            cached = state["jev_cache"].get(key)
            if cached and time.monotonic() - cached[0] < 300:
                return cached[1]
            persisted = await run_in_threadpool(state["store"].cached_judgment, key)
            if persisted is not None:
                state["jev_cache"][key] = (time.monotonic(), persisted)
                return persisted
            result = {"state": context, "judgment": await run_in_threadpool(JevClient().judge, context), "heuristic": row["jev"], "input_hash": key, "dataset_id": state["dataset_id"]}
            await run_in_threadpool(state["store"].save_judgment, key, result)
            if len(state["jev_cache"]) >= 500:
                state["jev_cache"].pop(next(iter(state["jev_cache"])))
            state["jev_cache"][key] = (time.monotonic(), result)
            return result

    @router.post("/simulate", response_class=JSONResponse)
    async def simulation(body: SimulateRequest, state: State) -> dict:
        record(state, body.identity_id)
        try:
            result = await run_in_threadpool(simulate, state["directory"], body.identity_id, body.change.model_dump())
        except (KeyError, ValueError) as exc:
            raise HTTPException(422, detail={"code": "invalid_change", "message": str(exc)}) from exc
        return await run_in_threadpool(state["store"].simulation, {**result, "dataset_id": state["dataset_id"], "identity_id": body.identity_id, "snapshot_version": state["snapshot_version"]})

    @router.post("/decisions", response_class=JSONResponse)
    async def decide(body: DecisionRequest, request: Request, state: State) -> dict:
        def commit_current() -> dict:
            with request.app.state.run_manager.activation_lock:
                if state is not request.app.state.resources:
                    raise ValueError("The active run changed while recording; rerun the simulation")
                return state["store"].decide(body.model_dump(), state["dataset_id"], {r["id"]: r["name"] for r in state["world"]["identities"]}, state["snapshot_version"])
        try:
            return await run_in_threadpool(commit_current)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, detail={"code": "decision_conflict", "message": str(exc)}) from exc

    @router.post("/assessments", response_class=JSONResponse)
    async def begin_assessment(body: AssessmentRequest, request: Request) -> JSONResponse:
        try:
            payload, code = await run_in_threadpool(start_assessment, request.app, body.idempotency_key)
        except RuntimeError as exc:
            raise HTTPException(409, detail={"code": "assessment_busy", "message": str(exc)}) from exc
        except ValueError as exc:
            raise HTTPException(422, detail={"code": "invalid_assessment", "message": str(exc)}) from exc
        return JSONResponse(payload, status_code=code)

    @router.get("/assessments/current", response_class=JSONResponse)
    async def current_assessment(request: Request) -> dict:
        return await run_in_threadpool(latest_assessment, request.app.state.run_manager)

    @router.get("/assessments/{assessment_id}", response_class=JSONResponse)
    async def one_assessment(assessment_id: str, request: Request) -> dict:
        def read() -> dict:
            job = request.app.state.run_manager.get(assessment_id)
            if job.get("command") != "assess":
                raise KeyError(assessment_id)
            return assessment_view(job)
        try:
            return await run_in_threadpool(read)
        except KeyError as exc:
            raise HTTPException(404, "Assessment not found") from exc

    @router.post("/assessments/{assessment_id}/cancel", response_class=JSONResponse)
    async def cancel_assessment(assessment_id: str, request: Request) -> dict:
        def stop() -> dict:
            job = request.app.state.run_manager.get(assessment_id)
            if job.get("command") != "assess":
                raise KeyError(assessment_id)
            return assessment_view(request.app.state.run_manager.cancel(assessment_id))
        try:
            return await run_in_threadpool(stop)
        except KeyError as exc:
            raise HTTPException(404, "Assessment not found") from exc

    @router.get("/decisions", response_class=JSONResponse, response_model=Page)
    async def decisions(state: State, q: str = Query("", max_length=200), identity_id: str = "", decision: Literal["", "accept", "reject", "defer", "apply", "hold"] = "", actor: Literal["", "human", "machine"] = "", limit: int = Query(40, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
        rows = await run_in_threadpool(state["store"].decisions)
        def machine(row: dict) -> bool:
            return row.get("actor_type") == "machine" or row.get("source") == "automatic_policy"
        return page([r for r in rows if (not identity_id or r["identity_id"] == identity_id) and (not decision or r["decision"] == decision) and (not actor or (actor == "machine") == machine(r))], q, limit, offset)

    @router.get("/approvals", response_class=JSONResponse)
    async def legacy(state: State) -> dict:
        return {"approvals": await run_in_threadpool(state["store"].legacy), "legacy": True}

    @router.post("/approvals", response_class=JSONResponse)
    async def legacy_write() -> dict:
        raise HTTPException(410, "Use /api/decisions with a completed simulation and rationale")

    @router.get("/evaluation", response_class=JSONResponse)
    async def evaluation(state: State) -> dict:
        unavailable = state["run"].get("evaluation_status") == "unavailable"
        benchmark, benchmark_robustness = (None, None)
        if unavailable:
            from entitleguard.report import load_original_benchmark
            benchmark, benchmark_robustness = load_original_benchmark(_benchmark_reference(state))
        return {"metrics": {} if unavailable else state["metrics"], "robustness": None if unavailable else state.get("robustness"), "benchmark": benchmark, "benchmark_robustness": benchmark_robustness, "run": state["run"], "dataset_id": state["dataset_id"], "evaluation_note": state["run"].get("evaluation_note"), "baseline_evaluation": state.get("baseline_evaluation")}

    @router.get("/export", response_class=Response)
    async def export(state: State, format: Literal["json", "csv", "html"] = "json") -> Response:
        from entitleguard.report import export_bundle
        from entitleguard.report import load_original_benchmark
        metrics = state["metrics"]
        notice = None
        if not metrics or state["run"].get("evaluation_status") == "unavailable":
            metrics, _robustness = load_original_benchmark(_benchmark_reference(state))
            if not metrics:
                raise HTTPException(409, detail={"code": "evaluation_unavailable", "message": "No compatible evaluation is available. Complete an offline experiment first."})
            notice = _benchmark_notice(state)
        content = await run_in_threadpool(lambda: export_bundle(state["world"], state["analysis"], metrics, format, notice))
        return Response(content, media_type={"json": "application/json", "csv": "text/csv", "html": "text/html"}[format], headers={"Content-Disposition": f'attachment; filename="entitleguard-report.{format}"'})

    application.include_router(router)
    application.include_router(build_job_router(initialize, baseline_loader))
    return application


app = create_app()
