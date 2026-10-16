"""Versioned, atomic artifacts and compatibility checks for offline runs."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
from importlib.metadata import version
from datetime import datetime
from datetime import timezone
from pathlib import Path

from config import JEV_PINNED_MODEL
from config import JEV_SCHEMA_VERSION
from config import RESULTS_DIR

SCHEMA_VERSION = "entitle-artifacts-v2"
GENERATOR_VERSION = "synthetic-v2"
POLICY_VERSION = "source-aware-v2"
MODEL_VERSION = "isolation-forest-100-v2"


def canonical_hash(payload: object) -> str:
    """Stable content digest; reject non-finite JSON values."""
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def dataset_hash(world: dict) -> str:
    """Hash the complete input snapshot, including labels and split manifest."""
    return canonical_hash(world)


def code_hash() -> str:
    """Invalidate caches when a computational implementation changes."""
    root = Path(__file__).resolve().parent
    names = ("generate.py", "catalog.py", "policy.py", "simulate.py", "drift.py", "fusion.py", "jev.py", "pipeline.py", "behavior.py", "evaluate.py", "artifacts.py", "holdout.py")
    return canonical_hash({**{name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}, "config.py": hashlib.sha256((root.parent / "config.py").read_bytes()).hexdigest()})


def provenance(world: dict) -> dict:
    """Record all compatibility inputs without variable timestamps."""
    configuration = {key: world["meta"].get(key) for key in ("seed", "as_of", "history_start", "population", "splits")}
    return {
        "dataset_id": f"synthetic-{dataset_hash(world)[:16]}",
        "dataset_hash": dataset_hash(world),
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "policy_version": POLICY_VERSION,
        "model_version": MODEL_VERSION,
        "question_schema_version": JEV_SCHEMA_VERSION,
        "optional_live_model": JEV_PINNED_MODEL,
        "judge_mode": "heuristic",
        "configuration": configuration,
        "configuration_hash": canonical_hash(configuration),
        "implementation_hash": code_hash(),
        "python_version": platform.python_version(),
        "dependency_versions": {name: version(name) for name in ("numpy", "scikit-learn")},
    }


def compatible(payload: dict, world: dict) -> bool:
    """An unversioned artifact is stale, even if its file exists."""
    return payload.get("_provenance") == provenance(world)


def atomic_write(path: Path, payload: dict) -> None:
    """Replace a complete JSON file; never publish partially written JSON."""
    atomic_text(path, json.dumps(payload, indent=2, allow_nan=False))


def atomic_text(path: Path, content: str) -> None:
    """Atomically replace a UTF-8 artifact after flushing its complete contents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path) -> dict | None:
    """Read an artifact, treating invalid/incomplete files as unavailable."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def validate_world(world: dict) -> None:
    """Reject duplicate IDs, dangling catalogue references and split leakage."""
    tables = {}
    for name in ("identities", "roles", "groups", "permissions", "resources"):
        ids = [row["id"] for row in world[name]]
        if len(ids) != len(set(ids)):
            raise ValueError(f"Duplicate {name} ID")
        tables[name] = set(ids)
    for row in world["permissions"]:
        if row["resource_id"] not in tables["resources"]:
            raise ValueError("Unknown resource")
    for row in world["roles"]:
        if not (set(row["required_permission_ids"]) | set(row["grant_permission_ids"])) <= tables["permissions"]:
            raise ValueError("Unknown role permission")
    for row in world["groups"]:
        if not set(row["role_ids"]) <= tables["roles"]:
            raise ValueError("Unknown group role")
    for row in world["identities"]:
        if row["split"] not in {"train", "validation", "test"}:
            raise ValueError("Invalid identity split")
        if row["role_id"] not in tables["roles"] or not set(row["group_ids"]) <= tables["groups"]:
            raise ValueError("Unknown identity source")
        if not set(row["direct_role_ids"]) <= tables["roles"]:
            raise ValueError("Unknown direct role")
        for grant in row["temporary_grants"]:
            if grant["permission_id"] not in tables["permissions"]:
                raise ValueError("Unknown temporary permission")
        for historical in row.get("role_history", []):
            if historical["role_id"] not in tables["roles"] or not set(historical["group_ids"]) <= tables["groups"]:
                raise ValueError("Unknown historical source")
        for field in ("extra_permission_ids", "deny_permission_ids"):
            if not set(row[field]) <= tables["permissions"]:
                raise ValueError("Unknown identity permission")
    for row in world["workflows"]:
        if not set(row["role_ids"]) <= tables["roles"] or not set(row["required_permission_ids"]) <= tables["permissions"]:
            raise ValueError("Unknown workflow reference")
    for row in [*world["labels"], *world["usage"], *world["exceptions"]]:
        if row["identity_id"] not in tables["identities"] or row["permission_id"] not in tables["permissions"]:
            raise ValueError("Unknown case reference")
    splits = world["meta"].get("splits")
    if splits is not None:
        expected = {name: sorted(row["id"] for row in world["identities"] if row["split"] == name) for name in ("train", "validation", "test")}
        if splits != expected:
            raise ValueError("Split manifest disagrees with identity assignments")


def run_metadata(world: dict, analysis: dict | None = None) -> dict:
    """Public run metadata with explicit cache state."""
    return {**provenance(world), "analysis_status": "ready" if analysis is not None and compatible(analysis, world) else "stale_or_missing", "population": world["meta"].get("population", {}), "as_of": world["meta"]["as_of"], "seed": world["meta"]["seed"]}


def load_metrics(world: dict, analysis: dict | None = None) -> dict | None:
    """Return metrics only when both input snapshot and implementation match."""
    payload = read_json(RESULTS_DIR / "metrics.json")
    if analysis is not None and not compatible(analysis, world):
        return None
    return payload if payload is not None and compatible(payload, world) else None


def publish_manifest(world: dict, analysis: dict, metrics: dict) -> dict:
    """Publish completion marker after all three artifacts validate."""
    if not compatible(analysis, world) or not compatible(metrics, world):
        raise ValueError("Cannot publish mismatched artifacts")
    manifest = {**run_metadata(world, analysis), "status": "completed", "created_at": datetime.now(timezone.utc).isoformat(), "analysis_hash": canonical_hash(analysis), "metrics_hash": canonical_hash(metrics)}
    atomic_write(RESULTS_DIR / "manifest.json", manifest)
    return manifest


def compatible_robustness(payload: dict, world: dict) -> bool:
    """A suite applies only to a matching member snapshot and implementation."""
    reference = payload.get("_provenance", {})
    expected = provenance(world)
    excluded = {"dataset_id", "dataset_hash", "configuration", "configuration_hash"}
    if {key: value for key, value in reference.items() if key not in excluded} != {key: value for key, value in expected.items() if key not in excluded}:
        return False
    if payload.get("as_of") != world["meta"]["as_of"]:
        return False
    return any(row.get("dataset_id") == expected["dataset_id"] and row.get("seed") == world["meta"]["seed"] for row in payload.get("runs", []))


def load_robustness(world: dict, results_dir: Path | None = None) -> dict | None:
    """Load a compatible suite from the active run's directory, if available."""
    payload = read_json((results_dir or RESULTS_DIR) / "robustness.json")
    return payload if payload is not None and compatible_robustness(payload, world) else None
