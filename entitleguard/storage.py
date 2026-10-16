"""Transactional local simulation and analyst decision ledger."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4


class Ledger:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS approvals (id INTEGER PRIMARY KEY AUTOINCREMENT,identity_id TEXT NOT NULL,permission_id TEXT NOT NULL,outcome TEXT NOT NULL,analyst TEXT NOT NULL,created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS simulations (id TEXT PRIMARY KEY,dataset_id TEXT NOT NULL,payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY,simulation_id TEXT NOT NULL REFERENCES simulations(id),idempotency_key TEXT UNIQUE NOT NULL,request TEXT NOT NULL,payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS judgments (cache_key TEXT PRIMARY KEY,created_at TEXT NOT NULL,payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS assessment_runs (id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE, status TEXT NOT NULL, payload TEXT NOT NULL);
                PRAGMA user_version=1;
            """)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def legacy(self) -> list[dict]:
        with self.connection() as db:
            return [{**dict(row), "legacy": True, "applied": False} for row in db.execute("SELECT * FROM approvals ORDER BY id DESC")]

    def simulation(self, payload: dict) -> dict:
        payload = {**payload, "simulation_id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat()}
        with self.connection() as db:
            db.execute("INSERT INTO simulations VALUES (?,?,?)", (payload["simulation_id"], payload["dataset_id"], json.dumps(payload)))
        return payload

    def decide(self, request: dict, dataset_id: str, identity_names: dict[str, str], snapshot_version: str | None = None) -> dict:
        canonical = json.dumps(request, sort_keys=True)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT request,payload FROM decisions WHERE idempotency_key=?", (request["idempotency_key"],)).fetchone()
            if existing:
                if existing["request"] != canonical:
                    raise ValueError("Idempotency key already belongs to a different decision")
                return json.loads(existing["payload"])
            row = db.execute("SELECT * FROM simulations WHERE id=?", (request["simulation_id"],)).fetchone()
            if not row:
                raise LookupError("Unknown simulation")
            if row["dataset_id"] != dataset_id:
                raise ValueError("Simulation is stale; rerun against the current dataset")
            simulation = json.loads(row["payload"])
            if snapshot_version is not None and simulation.get("snapshot_version") != snapshot_version:
                raise ValueError("Simulation evidence is stale; rerun the simulation")
            if request["decision"] == "accept" and not simulation["safe_to_remove"]:
                raise ValueError("Only a verified safe simulation can be accepted; reject or defer instead")
            previous = db.execute("SELECT id FROM decisions WHERE simulation_id=? ORDER BY rowid DESC LIMIT 1", (request["simulation_id"],)).fetchone()
            record = {**request, "supersedes_decision_id": previous[0] if previous else None, "id": str(uuid4()), "identity_id": simulation["identity_id"],
                      "identity_name": identity_names[simulation["identity_id"]], "dataset_id": dataset_id,
                      "change": simulation["change"], "safe_to_remove": simulation["safe_to_remove"],
                      "created_at": datetime.now(timezone.utc).isoformat(), "applied": False,
                      "analyst_is_demo_label": True, "simulation": simulation}
            db.execute("INSERT INTO decisions VALUES (?,?,?,?,?)", (record["id"],request["simulation_id"], request["idempotency_key"], canonical, json.dumps(record)))
        return record

    def cached_judgment(self, key: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT created_at,payload FROM judgments WHERE cache_key=?", (key,)).fetchone()
        if row and (datetime.now(timezone.utc) - datetime.fromisoformat(row["created_at"])).total_seconds() < 300:
            return json.loads(row["payload"])
        return None

    def save_judgment(self, key: str, payload: dict) -> None:
        with self.connection() as db:
            db.execute("INSERT OR REPLACE INTO judgments VALUES (?,?,?)", (key, datetime.now(timezone.utc).isoformat(), json.dumps(payload)))
            db.execute("DELETE FROM judgments WHERE rowid NOT IN (SELECT rowid FROM judgments ORDER BY created_at DESC LIMIT 500)")

    def decisions(self) -> list[dict]:
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload FROM decisions ORDER BY rowid DESC")]

    def import_assessment(self, run: dict, decisions: list[dict]) -> dict:
        """Store one finished automatic run and its decisions, once.

        Live access stays unchanged. `applied` remains false; `applied_in_simulation`
        records whether the saved copy contains the removal.
        """
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT payload FROM assessment_runs WHERE id=?", (run["id"],)).fetchone()
            if existing:
                return json.loads(existing["payload"])
            for decision in decisions:
                simulation = decision["simulation_record"]
                db.execute(
                    "INSERT OR IGNORE INTO simulations VALUES (?,?,?)",
                    (simulation["simulation_id"], simulation["dataset_id"], json.dumps(simulation)),
                )
                request = {
                    "idempotency_key": decision["idempotency_key"],
                    "decision": decision["decision"],
                    "run_id": decision["run_id"],
                    "permission_id": decision["permission_id"],
                    "actor_type": "machine",
                }
                stored = {key: value for key, value in decision.items() if key != "simulation_record"}
                canonical = json.dumps(request, sort_keys=True)
                db.execute(
                    "INSERT OR IGNORE INTO decisions VALUES (?,?,?,?,?)",
                    (decision["id"], decision["simulation_id"], decision["idempotency_key"], canonical, json.dumps(stored)),
                )
            db.execute(
                "INSERT INTO assessment_runs VALUES (?,?,?,?)",
                (run["id"], run.get("idempotency_key"), run["status"], json.dumps(run)),
            )
        return run

    def assessment(self, run_id: str) -> dict | None:
        """Return one stored assessment summary, without its decision bodies."""
        with self.connection() as db:
            row = db.execute("SELECT payload FROM assessment_runs WHERE id=?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None
