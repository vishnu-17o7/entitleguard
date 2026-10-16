"""Self-contained, escaped offline evaluation exports."""
from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from config import RESULTS_DIR
from entitleguard.artifacts import read_json
from entitleguard.artifacts import run_metadata


def load_original_benchmark(reference: dict | None, results_dir: Path | None = None) -> tuple[dict | None, dict | None]:
    """Return the saved benchmark when it belongs to the dataset named by reference.

    A remediated snapshot does not receive a new accuracy score. The caller
    may still show this artifact when its dataset hash or dataset label matches.
    """
    reference = reference or {}
    folder = results_dir or RESULTS_DIR
    metrics = read_json(folder / "metrics.json")
    if not metrics or "systems" not in metrics:
        return None, None
    provenance = metrics.get("_provenance") or {}
    full = provenance.get("dataset_hash")
    label = provenance.get("dataset_id")
    matched = bool(reference.get("dataset_hash") and reference.get("dataset_hash") == full) or bool(reference.get("dataset_id") and reference.get("dataset_id") == label) or bool(reference.get("original_dataset_id") and reference.get("original_dataset_id") == full)
    if not matched:
        return None, None
    robustness = read_json(folder / "robustness.json")
    runs = (robustness or {}).get("runs") or []
    if not any(row.get("dataset_id") == label for row in runs):
        robustness = None
    return metrics, robustness


def safe_csv_cell(value: object) -> str:
    """Neutralize spreadsheet formulas, including leading whitespace tricks."""
    text = str(value)
    return f"'{text}" if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text


def export_bundle(world: dict, analysis: dict, metrics: dict, format: str = "json", notice: str | None = None) -> str:
    """Export the exact active run and predictions; HTML has no remote assets."""
    bundle = {"run": run_metadata(world, analysis), "metrics": metrics, "reproduce": f'python run.py all --seed {world["meta"]["seed"]} --as-of {world["meta"]["as_of"]}', "scope": "Synthetic offline demonstration; recorded decisions are not applied to access."}
    if notice:
        bundle["metrics_scope"] = "original_benchmark"
        bundle["notice"] = notice
    benchmark_id = (metrics.get("_provenance") or {}).get("dataset_id") or bundle["run"]["dataset_id"]
    if format == "json":
        return json.dumps(bundle, indent=2, allow_nan=False)
    if format == "csv":
        output = io.StringIO(newline="")
        fields = ("dataset_id", "identity_id", "permission_id", "system", "scenario", "expected", "predicted", "correct")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(fields)
        row_dataset = benchmark_id if notice else bundle["run"]["dataset_id"]
        for row in metrics.get("predictions", []):
            writer.writerow([safe_csv_cell(row_dataset if key == "dataset_id" else row.get(key, "")) for key in fields])
        return output.getvalue()
    if format != "html":
        raise ValueError("Export format must be json, csv or html")
    escape = html.escape
    rows = "".join(f'<tr><th scope="row">{escape(name)}</th><td>{row["precision"]}</td><td>{row["recall"]}</td><td>{row["f1"]}</td><td>{row["false_removals"]}</td><td>{row["unresolved_removals"]}</td><td>{row["harmful_reductions"]}</td><td>{row["workflow_preservation"]}</td></tr>' for name, row in metrics["systems"].items())
    limitations = "".join(f"<li>{escape(line)}</li>" for line in metrics.get("limitations", []))
    payload = escape(json.dumps(bundle, indent=2, allow_nan=False))
    identity = f'<p><strong>Original benchmark.</strong> {escape(notice)}</p><p>Benchmark dataset {escape(benchmark_id)}. Active snapshot {escape(bundle["run"]["dataset_id"])}.</p>' if notice else f'<p>Dataset {escape(bundle["run"]["dataset_id"])} · seed {world["meta"]["seed"]} · as of {escape(world["meta"]["as_of"])}</p>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>EntitleGuard reproducible evaluation</title><style>body{{font:16px/1.5 system-ui,sans-serif;color:#24211f;background:#faf7f2;max-width:1100px;margin:40px auto;padding:20px}}h1,h2{{line-height:1.2}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px}}@media print{{body{{margin:0;background:white}}details{{display:block}}}}</style></head><body><h1>EntitleGuard evaluation</h1><p>Offline heuristic evaluation · synthetic data · scores are not calibrated probabilities.</p>{identity}<p>Held-out labeled grants: {metrics["labeled_cases"]}. Workflow preservation counts individual initially executable workflows; only remove recommendations are applied. Reduce requires a concrete narrowing proposal.</p><table><caption>Held-out comparison; ratios range from 0 to 1</caption><thead><tr><th scope="col">System</th><th scope="col">Precision</th><th scope="col">Recall</th><th scope="col">F1</th><th scope="col">False removals</th><th scope="col">Unresolved removals</th><th scope="col">Harmful reductions</th><th scope="col">Workflow preservation</th></tr></thead><tbody>{rows}</tbody></table><h2>Limitations</h2><ul>{limitations}</ul><h2>Reproduction</h2><pre>{escape(bundle["reproduce"])}</pre><h2>Complete machine-readable evidence</h2><p>Includes configuration, versions, metric definitions, per-case predictions, confusion matrices, intervals and scenario errors. Times and creation dates vary between runs.</p><pre id="reproduction-bundle">{payload}</pre></body></html>'''
