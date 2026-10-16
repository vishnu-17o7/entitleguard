from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    """Return an unambiguous timestamp for the run log."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RunManager:
    """Run allowlisted offline experiments in isolated artifact directories."""

    def __init__(
        self,
        project_root: Path,
        results_root: Path,
        command_builder: Callable[[dict[str, Any]], list[str]] | None = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self.root = (results_root / "jobs").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.activation_lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._threads: list[threading.Thread] = []
        self._closing = False
        self._command_builder = command_builder or self._command
        for path in self.root.glob("*/job.json"):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
                if job.get("id") != path.parent.name:
                    continue
                if job.get("status") in {"queued", "running", "cancelling"}:
                    job.update(status="interrupted", completed_at=_now())
                self._jobs[job["id"]] = job
                self._persist(job)
            except (OSError, ValueError, KeyError, TypeError):
                continue

    def _command(self, job: dict[str, Any]) -> list[str]:
        args = [sys.executable, "-B", "-u", str(self.project_root / "run.py"), job["command"]]
        args.extend(["--seed", str(job["seed"]), "--as-of", job["as_of"]])
        return args

    def _persist(self, job: dict[str, Any]) -> None:
        directory = self.root / job["id"]
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "job.json"
        temporary = directory / "job.json.tmp"
        temporary.write_text(json.dumps(job, indent=2), encoding="utf-8")
        temporary.replace(target)

    def _copy(self, job: dict[str, Any]) -> dict[str, Any]:
        return json.loads(json.dumps(job))

    def list(self) -> list[dict[str, Any]]:
        """List recent jobs without exposing local paths or environment values."""
        with self._lock:
            return [self._copy(job) for job in sorted(self._jobs.values(), key=lambda row: row["created_at"], reverse=True)[:30]]

    def get(self, job_id: str) -> dict[str, Any]:
        """Return one recorded job or raise KeyError."""
        with self._lock:
            return self._copy(self._jobs[job_id])

    def start(self, command: str, seed: int, as_of: str) -> dict[str, Any]:
        """Start one offline run; an active run cannot be overwritten."""
        if command not in {"all", "benchmark"}:
            raise ValueError("Choose a dataset run or a benchmark.")
        if isinstance(seed, bool) or not 0 <= seed <= 2**31 - 1:
            raise ValueError("Seed must be an integer between 0 and 2147483647.")
        datetime.strptime(as_of, "%Y-%m-%d")
        with self._lock:
            if self._closing:
                raise RuntimeError("The application is shutting down.")
            if any(row["status"] in {"queued", "running", "cancelling"} for row in self._jobs.values()):
                raise RuntimeError("An experiment is already running. Wait or cancel it first.")
            job = {
                "id": uuid.uuid4().hex,
                "command": command,
                "seed": seed,
                "as_of": as_of,
                "status": "queued",
                "created_at": _now(),
                "started_at": None,
                "completed_at": None,
                "exit_code": None,
                "output": "",
                "output_truncated": False,
                "activatable": False,
            }
            self._jobs[job["id"]] = job
            self._persist(job)
            thread = threading.Thread(target=self._work, args=(job["id"],), daemon=True)
            self._threads.append(thread)
            thread.start()
            return self._copy(job)

    def _work(self, job_id: str) -> None:
        process = None
        try:
            with self._lock:
                job = self._jobs[job_id]
                if job["status"] == "cancelled":
                    return
                env = os.environ.copy()
                env.update(
                    ENTITLEGUARD_DATA_DIR=str(self.root / job_id / "data"),
                    ENTITLEGUARD_RESULTS_DIR=str(self.root / job_id / "results"),
                    JEV_PROVIDER="heuristic",
                    PYTHONIOENCODING="utf-8",
                )
                process = subprocess.Popen(
                    self._command_builder(job),
                    cwd=self.project_root,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                self._processes[job_id] = process
                job.update(status="running", started_at=_now())
                self._persist(job)
            assert process.stdout is not None
            for line in process.stdout:
                with self._lock:
                    job["output"] += line
                    if len(job["output"]) > 65536:
                        job["output"] = job["output"][-65536:]
                        job["output_truncated"] = True
                    self._persist(job)
            process.stdout.close()
            code = process.wait()
            with self._lock:
                cancelled = job["status"] == "cancelling"
                job.update(
                    status="cancelled" if cancelled else "succeeded" if code == 0 else "failed",
                    exit_code=code,
                    completed_at=_now(),
                    activatable=not cancelled and code == 0 and job["command"] == "all",
                )
                self._persist(job)
        except Exception as exc:
            with self._lock:
                job = self._jobs[job_id]
                job.update(status="failed", completed_at=_now(), activatable=False)
                job["output"] = f"{job['output']}\nRun failed: {type(exc).__name__}: {exc}"[-65536:]
                self._persist(job)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            with self._lock:
                self._processes.pop(job_id, None)

    def cancel(self, job_id: str) -> dict[str, Any]:
        """Stop only the child process owned by this manager."""
        with self._lock:
            job = self._jobs[job_id]
            if job["status"] == "queued":
                job.update(status="cancelled", completed_at=_now())
            elif job["status"] == "running":
                job["status"] = "cancelling"
                process = self._processes.get(job_id)
                if process is not None and process.poll() is None:
                    process.terminate()
            self._persist(job)
            return self._copy(job)

    def reserve(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Register one in-process assessment. The second value is false when the key already exists."""
        if job.get("command") != "assess":
            raise ValueError("Unsupported local command.")
        key = job.get("idempotency_key")
        if not isinstance(key, str) or not 8 <= len(key) <= 100:
            raise ValueError("Idempotency key must be 8 to 100 characters.")
        with self._lock:
            if self._closing:
                raise RuntimeError("The application is shutting down.")
            for existing in self._jobs.values():
                if existing.get("idempotency_key") == key:
                    return self._copy(existing), False
            if any(row["status"] in {"queued", "running", "cancelling"} for row in self._jobs.values()):
                raise RuntimeError("An experiment is already running. Wait or cancel it first.")
            self._jobs[job["id"]] = job
            self._persist(job)
            return self._copy(job), True

    def update_job(self, job_id: str, *, force: bool = False, **changes: Any) -> dict[str, Any]:
        """Update a recorded job. Terminal jobs ignore later writes unless forced."""
        with self._lock:
            job = self._jobs[job_id]
            if job["status"] in {"succeeded", "failed", "cancelled", "interrupted", "stale"} and not force:
                return self._copy(job)
            if job["status"] == "cancelling" and changes.get("status") not in {"cancelled", "cancelling"}:
                changes = {**changes, "status": "cancelled", "activatable": False}
                if not job.get("completed_at") and "completed_at" not in changes:
                    changes["completed_at"] = _now()
            job.update(changes)
            self._persist(job)
            return self._copy(job)

    def claim_running(self, job_id: str) -> bool:
        """Move a queued local job to running. A cancelled job stays cancelled."""
        with self._lock:
            job = self._jobs[job_id]
            if job["status"] != "queued":
                if job["status"] == "cancelling":
                    job.update(status="cancelled", completed_at=_now(), activatable=False)
                    self._persist(job)
                return False
            job.update(status="running", started_at=_now())
            self._persist(job)
            return True

    def by_idempotency(self, key: str) -> dict[str, Any] | None:
        """Return the newest local job stored under this key."""
        with self._lock:
            matches = [job for job in self._jobs.values() if job.get("idempotency_key") == key]
            if not matches:
                return None
            return self._copy(max(matches, key=lambda row: row["created_at"]))

    def track(self, thread: threading.Thread) -> None:
        """Join this worker when the application shuts down."""
        with self._lock:
            self._threads.append(thread)

    def completed_directory(self, job_id: str) -> Path:
        """Return artifacts only for a successful dataset or assessment run."""
        job = self.get(job_id)
        if not job["activatable"] or job["status"] != "succeeded":
            raise ValueError("Only a successful dataset run can be loaded.")
        return self.root / job_id

    def selected(self) -> str | None:
        """Read the selected run ID, without trusting a saved filesystem path."""
        path = self.root / "selected.json"
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        value = payload.get("job_id")
        if value is not None:
            self.completed_directory(value)
        return value

    def select(self, job_id: str | None) -> None:
        """Persist a previously validated selection atomically."""
        if job_id is not None:
            self.completed_directory(job_id)
        temporary = self.root / "selected.json.tmp"
        temporary.write_text(json.dumps({"job_id": job_id}), encoding="utf-8")
        temporary.replace(self.root / "selected.json")

    def close(self) -> None:
        """Cancel running experiments and wait briefly for their log writers."""
        with self._lock:
            self._closing = True
            active = [key for key, job in self._jobs.items() if job["status"] in {"queued", "running"}]
        for job_id in active:
            self.cancel(job_id)
        for thread in self._threads:
            thread.join(timeout=10)
