from datetime import datetime, timezone
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from ckg.evaluation.historical import (
    HistoricalRecord,
    build_historical_view,
    evaluate_cutoff,
    load_historical_records,
    predict_weaknesses,
)
from ckg.ingestion.cve.models import AffectedProduct


def _record(
    key: str,
    when: datetime,
    *,
    cwe: tuple[str, ...] = (),
    vendor: str = "acme",
    product: str = "webapp",
) -> HistoricalRecord:
    return HistoricalRecord(
        key=key,
        record_id=key,
        source_kind="fixture",
        source_digest=f"sha256:{key:0<64}",
        source_url="fixture://record",
        state="PUBLISHED",
        published_at=when,
        updated_at=when,
        known_at=when,
        title=f"Issue in {product}",
        description=f"{vendor} {product} input validation issue",
        products=(AffectedProduct(vendor, product, None, "fixture", aliases=(product,)),),
        cwe_ids=frozenset(cwe),
    )


def test_historical_loader_replays_pinned_objects() -> None:
    records = load_historical_records("datasets/evaluation/manifest.yaml")

    assert len(records) == 25
    assert all(record.source_digest.startswith("sha256:") for record in records)
    assert any(record.record_id == "CVE-2024-21626" for record in records)


def test_temporal_view_does_not_leak_future_records() -> None:
    old = _record("old", datetime(2025, 1, 1, tzinfo=timezone.utc), cwe=("CWE-79",))
    future = _record("future", datetime(2026, 2, 1, tzinfo=timezone.utc), cwe=("CWE-89",))
    view = build_historical_view(
        (old, future),
        cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert tuple(record.key for record in view.train) == ("old",)
    assert tuple(record.key for record in view.held_out) == ("future",)
    assert predict_weaknesses(future, view, baseline="graph-only-v1") == ("CWE-79",)


def test_empty_prediction_is_evaluated_failure_not_missing_metric() -> None:
    old = _record("old", datetime(2025, 1, 1, tzinfo=timezone.utc), cwe=("CWE-79",), vendor="oldco", product="oldapp")
    future = _record("future", datetime(2026, 2, 1, tzinfo=timezone.utc), cwe=("CWE-89",), vendor="newco", product="newapp")
    result = evaluate_cutoff(
        (old, future),
        cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        baseline="graph-only-v1",
    )

    assert result.status == "evaluated"
    assert result.n_judged == 1
    assert result.predictions["future"] == ()
    assert result.metrics["recall_at_k"] == 0.0


def test_bm25_baseline_is_dependency_free_and_deterministic() -> None:
    records = (
        _record("old", datetime(2025, 1, 1, tzinfo=timezone.utc), cwe=("CWE-79",), product="oldapp"),
        _record("future", datetime(2026, 2, 1, tzinfo=timezone.utc), cwe=("CWE-89",), product="newapp"),
    )
    first = evaluate_cutoff(
        records,
        cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        baseline="bm25-v1",
    )
    second = evaluate_cutoff(
        records,
        cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        baseline="bm25-v1",
    )

    assert first.status == "evaluated"
    assert first.predictions == second.predictions
    assert first.metrics == second.metrics


def test_rejected_records_do_not_become_future_observed_labels() -> None:
    rejected = replace(
        _record("rejected", datetime(2026, 2, 1, tzinfo=timezone.utc), cwe=("CWE-79",)),
        state="REJECTED",
    )
    result = evaluate_cutoff(
        (rejected,),
        cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        baseline="keyword-v1",
    )

    assert result.status == "not_evaluable"
    assert result.n_judged == 0


def test_loader_fails_closed_on_inventory_or_object_digest(tmp_path: Path) -> None:
    payload = {
        "cveMetadata": {"cveId": "CVE-2099-0001", "state": "PUBLISHED"},
        "containers": {"cna": {"problemTypes": [], "affected": []}},
    }
    object_path = tmp_path / "objects"
    object_path.mkdir()
    raw_path = object_path / ("a" * 64)
    raw_path.write_text(json.dumps(payload), encoding="utf-8")
    manifest = {
        "cve_snapshot": {
            "root": str(tmp_path),
            "object_count": 1,
            "inventory_digest": "sha256:" + "0" * 64,
            "object_digests": ["sha256:" + "a" * 64],
        }
    }
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="inventory_digest"):
        load_historical_records(manifest_path)

    manifest["cve_snapshot"]["inventory_digest"] = "sha256:" + hashlib.sha256(
        ("sha256:" + "a" * 64).encode("utf-8")
    ).hexdigest()
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        load_historical_records(manifest_path)


def test_cli_rejects_manifest_without_cutoffs(tmp_path: Path) -> None:
    from ckg.evaluation.cli import main

    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text("cve_snapshot: {}\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="cutoffs"):
        main(["--manifest", str(manifest_path)])
