from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from entitleguard.jobs import RunManager


class RunManagerTests(unittest.TestCase):
    def wait_for_finish(self, manager: RunManager, job_id: str) -> dict:
        """Wait for a real child to finish within a bounded test deadline."""
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            row = manager.get(job_id)
            if row["status"] not in {"queued", "running", "cancelling"}:
                return row
            time.sleep(0.02)
        self.fail("Child process did not finish")

    def test_success_and_isolated_environment(self) -> None:
        """Jobs receive separate directories and offline AI configuration."""
        with tempfile.TemporaryDirectory() as folder:
            code = "import os,json; print(json.dumps({k:os.environ[k] for k in ['ENTITLEGUARD_DATA_DIR','JEV_PROVIDER']}))"
            manager = RunManager(ROOT, Path(folder), lambda job: [sys.executable, "-c", code])
            try:
                job = manager.start("all", 42, "2026-10-14")
                result = self.wait_for_finish(manager, job["id"])
                self.assertEqual(result["status"], "succeeded")
                self.assertTrue(result["activatable"])
                environment = json.loads(result["output"])
                self.assertEqual(environment["JEV_PROVIDER"], "heuristic")
                self.assertIn(job["id"], environment["ENTITLEGUARD_DATA_DIR"])
                manager.select(job["id"])
                self.assertEqual(manager.selected(), job["id"])
            finally:
                manager.close()

    def test_failed_run_cannot_be_selected(self) -> None:
        """Nonzero exits remain inspectable but never replace the active run."""
        with tempfile.TemporaryDirectory() as folder:
            manager = RunManager(ROOT, Path(folder), lambda job: [sys.executable, "-c", "raise SystemExit(3)"])
            try:
                job = manager.start("all", 42, "2026-10-14")
                result = self.wait_for_finish(manager, job["id"])
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["exit_code"], 3)
                with self.assertRaises(ValueError):
                    manager.select(job["id"])
                with self.assertRaises(KeyError):
                    manager.completed_directory("../../elsewhere")
            finally:
                manager.close()

    def test_cancellation_and_duplicate_start(self) -> None:
        """One owned process can be cancelled without launching duplicate work."""
        with tempfile.TemporaryDirectory() as folder:
            manager = RunManager(ROOT, Path(folder), lambda job: [sys.executable, "-c", "import time; time.sleep(30)"])
            try:
                job = manager.start("all", 42, "2026-10-14")
                with self.assertRaises(RuntimeError):
                    manager.start("all", 43, "2026-10-14")
                manager.cancel(job["id"])
                self.assertEqual(self.wait_for_finish(manager, job["id"])["status"], "cancelled")
            finally:
                manager.close()

    def test_interrupted_job_recovery(self) -> None:
        """Restarting marks old running records interrupted without killing PIDs."""
        with tempfile.TemporaryDirectory() as folder:
            job_path = Path(folder) / "jobs" / "old" / "job.json"
            job_path.parent.mkdir(parents=True)
            job_path.write_text(json.dumps({"id": "old", "status": "running", "created_at": "2026-10-14", "activatable": False}), encoding="utf-8")
            manager = RunManager(ROOT, Path(folder))
            try:
                self.assertEqual(manager.get("old")["status"], "interrupted")
            finally:
                manager.close()


if __name__ == "__main__":
    unittest.main()
