"""EntitleGuard offline generation, evaluation, benchmark, report and console CLI."""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import AS_OF
from config import DATA_DIR
from config import HOST
from config import PORT
from config import RESULTS_DIR
from config import SEED
from entitleguard.artifacts import atomic_write
from entitleguard.artifacts import atomic_text
from entitleguard.artifacts import compatible
from entitleguard.artifacts import provenance
from entitleguard.artifacts import publish_manifest
from entitleguard.artifacts import read_json
from entitleguard.artifacts import validate_world
from entitleguard.evaluate import benchmark
from entitleguard.evaluate import evaluate
from entitleguard.generate import generate_enterprise
from entitleguard.pipeline import analyze_world
from entitleguard.report import export_bundle


def _write(path: Path, payload: dict) -> None:
    """Compatibility wrapper for atomic writes."""
    atomic_write(path, payload)


def load_world() -> dict:
    """Load the active snapshot, validating references, or generate defaults."""
    path = DATA_DIR / "enterprise.json"
    world = read_json(path)
    if path.exists() and world is None:
        raise ValueError("The dataset artifact is corrupt; generate a fresh run explicitly.")
    if world is None:
        world = generate_enterprise()
        atomic_write(DATA_DIR / "enterprise.json", world)
    validate_world(world)
    return world


def load_analysis() -> dict:
    """Recompute unversioned/stale caches before exposing recommendations."""
    world = load_world()
    analysis = read_json(DATA_DIR / "analysis.json")
    if analysis is None or not compatible(analysis, world):
        analysis = analyze_world(world)
        atomic_write(DATA_DIR / "analysis.json", analysis)
    return analysis


def cmd_generate(seed: int = SEED, as_of: str = AS_OF) -> None:
    """Write a validated synthetic snapshot atomically."""
    world = generate_enterprise(seed, as_of)
    validate_world(world)
    atomic_write(DATA_DIR / "enterprise.json", world)
    print(f"Generated seed={seed} as_of={as_of} identities={len(world['identities'])}; existing caches require matching provenance.")


def cmd_analyze() -> None:
    """Score drift, training-only peers, heuristic judgments and simulations."""
    world = load_world()
    analysis = analyze_world(world)
    atomic_write(DATA_DIR / "analysis.json", analysis)
    print(f"Analyzed findings={analysis['overview']['findings']} (offline heuristic)")


def cmd_evaluate() -> None:
    """Evaluate held-out identities and publish a completed run manifest."""
    world = load_world()
    analysis = load_analysis()
    metrics = evaluate(world, analysis)
    atomic_write(RESULTS_DIR / "metrics.json", metrics)
    atomic_text(RESULTS_DIR / "report.html", export_bundle(world, analysis, metrics, "html"))
    manifest = publish_manifest(world, analysis, metrics)
    atomic_write(RESULTS_DIR / "evaluation_manifest.json", {**manifest, "dataset": {"mode": "synthetic", "name": "EntitleGuard enterprise", "rows": len(world["identities"])}, "split": {"strategy": "frozen identity-level train/validation/test", "counts": metrics["split_counts"]}})
    print(f"Evaluated labeled_test={metrics['labeled_cases']} mode=heuristic full_f1={metrics['systems']['full']['f1']}")


def cmd_all(seed: int = SEED, as_of: str = AS_OF) -> None:
    """Generate, analyze and evaluate one reproducible world."""
    cmd_generate(seed, as_of)
    cmd_analyze()
    cmd_evaluate()


def cmd_serve() -> None:
    """Serve the local console without auto-reload."""
    import uvicorn

    uvicorn.run("api:app", host=HOST, port=PORT, reload=False, app_dir=str(ROOT))


def main(argv: list[str] | None = None) -> None:
    """Parse root-safe commands; never opt into paid live calls implicitly."""
    parser = argparse.ArgumentParser(description="EntitleGuard synthetic offline demonstration. Paths are anchored to this project, independent of the current directory.")
    sub = parser.add_subparsers(dest="command")
    for name in ("generate", "analyze", "evaluate", "all", "benchmark", "report", "serve", "ui"):
        command = sub.add_parser(name)
        if name in {"generate", "all", "benchmark"}:
            command.add_argument("--seed", type=int, default=SEED)
            command.add_argument("--as-of", default=AS_OF, type=lambda value: date.fromisoformat(value).isoformat())
        if name == "benchmark":
            command.add_argument("--repeats", type=int, default=5, choices=range(1, 11))
        if name == "report":
            command.add_argument("--format", choices=("html", "json", "csv"), default="html")
            command.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    command = args.command or "all"
    if command in {"generate", "all"}:
        (cmd_generate if command == "generate" else cmd_all)(getattr(args, "seed", SEED), getattr(args, "as_of", AS_OF))
    elif command == "analyze":
        cmd_analyze()
    elif command == "evaluate":
        cmd_evaluate()
    elif command in {"serve", "ui"}:
        cmd_serve()
    elif command == "benchmark":
        payload = benchmark(list(range(args.seed, args.seed + args.repeats)), args.as_of)
        payload["_provenance"] = provenance(generate_enterprise(args.seed, args.as_of))
        atomic_write(RESULTS_DIR / "robustness.json", payload)
        print(f"Saved {args.repeats}-seed offline robustness suite to {RESULTS_DIR / 'robustness.json'}")
    elif command == "report":
        world = load_world()
        analysis = load_analysis()
        metrics = read_json(RESULTS_DIR / "metrics.json")
        if metrics is None or not compatible(metrics, world):
            cmd_evaluate()
            metrics = read_json(RESULTS_DIR / "metrics.json")
        assert metrics is not None
        output = args.output or RESULTS_DIR / f"evaluation.{args.format}"
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        atomic_text(output, export_bundle(world, analysis, metrics, args.format))
        print(f"Exported {output}")


if __name__ == "__main__":
    main()
