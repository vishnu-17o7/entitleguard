"""Real isolated experiment lifecycle and benchmark API integration tests."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx

from api import create_app
from entitleguard.artifacts import provenance
from entitleguard.evaluate import benchmark
from entitleguard.generate import generate_enterprise
from entitleguard.pipeline import analyze_world


class JobApiTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.world = generate_enterprise(42, "2026-10-14")
        cls.analysis = analyze_world(cls.world)

    async def asyncSetUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.ledger = Path(self.folder.name) / "ledger.sqlite"
        await self.open_app()

    async def open_app(self) -> None:
        self.app = create_app(world=self.world, analysis=self.analysis, metrics={}, db_path=self.ledger)
        self.lifecycle = self.app.router.lifespan_context(self.app)
        await self.lifecycle.__aenter__()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://testserver")

    async def close_app(self) -> None:
        await self.client.aclose()
        await self.lifecycle.__aexit__(None, None, None)

    async def asyncTearDown(self) -> None:
        await self.close_app()
        self.folder.cleanup()

    async def completed(self, job_id: str, timeout: float = 45) -> dict:
        """Poll without blocking the event loop or waiting without a deadline."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = await self.client.get(f"/api/jobs/{job_id}")
            self.assertEqual(response.status_code, 200, response.text)
            job = response.json()
            if job["status"] not in {"queued", "running", "cancelling"}:
                self.assertEqual(job["status"], "succeeded", job["output"])
                return job
            await asyncio.sleep(0.05)
        self.fail("Experiment failed to finish within the bounded integration deadline")

    async def test_real_run_activation_restore_stale_decision_and_corruption(self) -> None:
        baseline_id = (await self.client.get("/api/run")).json()["dataset_id"]
        simulation = (await self.client.post("/api/simulate", json={"identity_id": "EMP-104", "change": {"type": "remove_group", "group_id": "grp-data-engineer"}})).json()
        started = await self.client.post("/api/jobs", json={"command": "all", "seed": 43, "as_of": "2026-10-15"})
        self.assertEqual(started.status_code, 202, started.text)
        job_id = started.json()["id"]
        self.assertEqual((await self.client.get("/api/run")).json()["dataset_id"], baseline_id)
        await self.completed(job_id)
        result = await self.client.get(f"/api/jobs/{job_id}/results")
        self.assertEqual(result.status_code, 200, result.text)
        self.assertTrue(result.json()["metrics"])
        activated = await self.client.post("/api/run/activate", json={"job_id": job_id})
        self.assertEqual(activated.status_code, 200, activated.text)
        selected_id = activated.json()["dataset_id"]
        self.assertNotEqual(selected_id, baseline_id)
        decision = await self.client.post("/api/decisions", json={"simulation_id": simulation["simulation_id"], "decision": "accept", "analyst": "Demo student", "rationale": "Previous simulation belongs to another input snapshot.", "idempotency_key": "stale-run-integration"})
        self.assertEqual(decision.status_code, 409, decision.text)
        self.assertEqual((await self.client.get("/api/decisions")).json()["total"], 0)
        await self.close_app()
        await self.open_app()
        restored = (await self.client.get("/api/run")).json()
        self.assertEqual(restored["dataset_id"], selected_id)
        self.assertEqual(restored["selected_job_id"], job_id)
        baseline = await self.client.post("/api/run/activate", json={"job_id": None})
        self.assertEqual(baseline.status_code, 200, baseline.text)
        self.assertEqual(baseline.json()["dataset_id"], baseline_id)
        metrics_path = self.app.state.run_manager.root / job_id / "results" / "metrics.json"
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        metrics["tampered"] = True
        metrics_path.write_text(json.dumps(metrics), encoding="utf-8")
        corrupt = await self.client.post("/api/run/activate", json={"job_id": job_id})
        self.assertEqual(corrupt.status_code, 409, corrupt.text)
        self.assertEqual((await self.client.get(f"/api/jobs/{job_id}/results")).status_code, 409)
        self.assertEqual((await self.client.get("/api/run")).json()["dataset_id"], baseline_id)

    async def test_benchmark_results_pending_compatible_stale_and_no_activation(self) -> None:
        baseline_id = (await self.client.get("/api/run")).json()["dataset_id"]
        manager = self.app.state.run_manager
        manager._command_builder = lambda job: [sys.executable, "-c", "import time; time.sleep(0.25)"]
        started = await self.client.post("/api/jobs", json={"command": "benchmark", "seed": 43, "as_of": "2026-10-15"})
        self.assertEqual(started.status_code, 202, started.text)
        job_id = started.json()["id"]
        self.assertEqual((await self.client.get(f"/api/jobs/{job_id}/results")).status_code, 409)
        await self.completed(job_id)
        self.assertEqual((await self.client.get(f"/api/jobs/{job_id}/results")).status_code, 409)
        payload = await asyncio.to_thread(benchmark, [43], "2026-10-15")
        payload["_provenance"] = await asyncio.to_thread(lambda: provenance(generate_enterprise(43, "2026-10-15")))
        path = manager.root / job_id / "results" / "robustness.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        response = await self.client.get(f"/api/jobs/{job_id}/results")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["robustness"]["runs"][0]["seed"], 43)
        self.assertEqual((await self.client.post("/api/run/activate", json={"job_id": job_id})).status_code, 409)
        self.assertEqual((await self.client.get("/api/run")).json()["dataset_id"], baseline_id)
        payload["as_of"] = "2000-01-01"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.assertEqual((await self.client.get(f"/api/jobs/{job_id}/results")).status_code, 409)
        self.assertEqual((await self.client.get("/api/run")).json()["dataset_id"], baseline_id)

    async def test_invalid_job_requests_and_unknown_ids(self) -> None:
        for body in ({"command": "serve"}, {"command": "all", "seed": True}, {"command": "all", "seed": -1}, {"command": "all", "seed": "43"}, {"command": "all", "as_of": "not-a-date"}, {"command": "all", "unknown": True}):
            response = await self.client.post("/api/jobs", json=body)
            self.assertEqual(response.status_code, 422, response.text)
        for url in ("/api/jobs/unknown", "/api/jobs/unknown/results"):
            self.assertEqual((await self.client.get(url)).status_code, 404)
        self.assertEqual((await self.client.post("/api/run/activate", json={"job_id": "unknown"})).status_code, 404)
        self.assertEqual((await self.client.post("/api/run/activate", json={"job_id": ""})).status_code, 422)


if __name__ == "__main__":
    unittest.main()
