"""Stable serialization for historical evaluation artifacts."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable

from ckg.evaluation.historical import EvaluationResult, HistoricalRecord


_CSV_FIELDS = (
    "cutoff",
    "baseline",
    "task",
    "status",
    "n_train",
    "n_held_out",
    "n_judged",
    "k",
    "precision_at_k",
    "recall_at_k",
    "mrr",
    "ndcg_at_k",
    "micro_f1",
    "macro_f1",
    "example_f1",
    "diagnostics",
)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def _result_row(result: EvaluationResult) -> dict[str, Any]:
    row: dict[str, Any] = {
        "cutoff": result.cutoff.isoformat().replace("+00:00", "Z"),
        "baseline": result.baseline,
        "task": result.task,
        "status": result.status,
        "n_train": result.n_train,
        "n_held_out": result.n_held_out,
        "n_judged": result.n_judged,
        "k": result.k,
        "diagnostics": list(result.diagnostics),
    }
    row.update(result.metrics)
    return row


def _prediction_rows(results: Iterable[EvaluationResult]) -> list[dict[str, Any]]:
    rows = []
    for result in results:
        cutoff = result.cutoff.isoformat().replace("+00:00", "Z")
        for record_key in sorted(result.truth):
            rows.append(
                {
                    "cutoff": cutoff,
                    "baseline": result.baseline,
                    "task": result.task,
                    "record_key": record_key,
                    "prediction": list(result.predictions.get(record_key, ())),
                    "future_observed_cwe": sorted(result.truth[record_key]),
                }
            )
    return rows


def _record_rows(records: Iterable[HistoricalRecord]) -> list[dict[str, Any]]:
    return [
        {
            "key": record.key,
            "record_id": record.record_id,
            "source_kind": record.source_kind,
            "source_digest": record.source_digest,
            "known_at": record.known_at.isoformat().replace("+00:00", "Z") if record.known_at else None,
            "published_at": record.published_at.isoformat().replace("+00:00", "Z") if record.published_at else None,
            "updated_at": record.updated_at.isoformat().replace("+00:00", "Z") if record.updated_at else None,
            "state": record.state,
            "cwe_ids": sorted(record.cwe_ids),
            "product_count": len(record.products),
        }
        for record in sorted(records, key=lambda item: item.key)
    ]


def write_evaluation_artifacts(
    output_dir: str | Path,
    *,
    manifest_path: str | Path,
    manifest_payload: dict[str, Any],
    records: Iterable[HistoricalRecord],
    results: Iterable[EvaluationResult],
    command: str,
) -> dict[str, Any]:
    """Write JSONL/CSV/JSON artifacts and return the deterministic summary."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    result_list = tuple(results)
    record_list = tuple(records)
    manifest_bytes = Path(manifest_path).read_bytes()
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    summary = {
        "schema_version": 1,
        "experiment_id": manifest_payload.get("experiment_id"),
        "task": "cve_to_cwe_temporal_link_prediction",
        "status": "evaluated" if any(item.status == "evaluated" for item in result_list) else "not_evaluable",
        "manifest_digest": manifest_digest,
        "git_revision": _git_revision(),
        "command": command,
        "record_count": len(record_list),
        "source_digests": sorted({record.source_digest for record in record_list}),
        "future_observed_labels": True,
        "human_gold_labels": False,
        "source_versions": manifest_payload.get("source_versions", {}),
        "source_snapshots": manifest_payload.get("source_snapshots", {}),
        "parser_version": manifest_payload.get("cve_snapshot", {}).get("parser_version"),
        "embedding_version": manifest_payload.get("embedding_version"),
        "model_version": manifest_payload.get("model_version"),
        "annotation_policy": manifest_payload.get("annotation_policy"),
        "baselines": sorted({item.baseline for item in result_list}),
        "cutoffs": sorted({item.cutoff.isoformat().replace("+00:00", "Z") for item in result_list}),
        "k_values": sorted({item.k for item in result_list}),
        "row_count": len(result_list),
        "diagnostics": [
            "Labels are parsed from the pinned source snapshot and are future-observed evaluation labels, not human adjudication.",
            "Records without a conservative known_at timestamp are excluded from temporal splits.",
        ],
    }
    _write_json(destination / "summary.json", summary)

    rows = [_result_row(result) for result in result_list]
    with (destination / "results.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    with (destination / "results.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                field: json.dumps(row[field], ensure_ascii=False, sort_keys=True)
                if field == "diagnostics"
                else row.get(field)
                for field in _CSV_FIELDS
            })

    prediction_rows = _prediction_rows(result_list)
    with (destination / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for row in prediction_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    _write_json(destination / "records.json", _record_rows(record_list))
    (destination / "README.md").write_text(
        f"""# Historical evaluation artifacts

Generated by `scripts/run_historical_evaluation.py`.

The task is temporal CVE-to-CWE link prediction. The evaluator replays only
records whose source snapshot digest is listed in the manifest. Labels in
`predictions.jsonl` are future-observed source labels, not human gold
annotations. A held-out record with no temporally visible evidence remains an
evaluated zero-prediction result; a cutoff with no judged records is marked
`not_evaluable`.

The graph-* rows are controlled deterministic ablations over parsed product,
source and CVE-to-CWE evidence. They are not sentence-transformer or learned
graph-embedding results.

Command used: `{command}`

Files: `summary.json`, `results.jsonl`, `results.csv`, `predictions.jsonl`,
and `records.json`.
""",
        encoding="utf-8",
    )
    return summary
