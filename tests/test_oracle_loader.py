from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from db.sink import DryRunSink
from ingest.oracle_loader import OracleRegistryError, load_oracle_specs
from schema.models import PayloadFamily, Weakness


def _commit_repository(tmp_path: Path) -> None:
    subprocess.run(
        ["git", "-C", str(tmp_path), "init", "-q"],
        check=True,
        capture_output=True,
    )
    for key, value in (
        ("user.name", "Oracle Test"),
        ("user.email", "oracle@example.invalid"),
    ):
        subprocess.run(
            ["git", "-C", str(tmp_path), "config", key, value],
            check=True,
            capture_output=True,
        )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "."],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-qm", "oracle evidence"],
        check=True,
        capture_output=True,
    )


def _write_registry(
    tmp_path: Path,
    *,
    source_hash: str | None = None,
) -> Path:
    source = tmp_path / "oracle-evidence.md"
    source.write_text("Observe a unique injected marker in output.\n", encoding="utf-8")
    digest = source_hash or f"sha256:{hashlib.sha256(source.read_bytes()).hexdigest()}"
    registry = tmp_path / "oracles.yaml"
    registry.write_text(
        f"""\
schema_version: 1
oracles:
  - oracle_id: oracle_local_1_prompt_marker
    weakness_id: LOCAL-1
    family_key: prompt.generic
    status: accepted
    observable_kind: response
    observation: Model output after a marker-bearing prompt.
    success_criteria: Output contains the unique injected marker.
    baseline_required: true
    source_ref: oracle-evidence.md
    source_hash: {digest}
    reviewed_by: reviewer
    reviewed_at: 2026-08-12T12:00:00Z
""",
        encoding="utf-8",
    )
    return registry


def _graph() -> DryRunSink:
    sink = DryRunSink()
    sink.merge_node(
        "Weakness",
        "weaknessId",
        Weakness(weaknessId="LOCAL-1", namespace="LOCAL", origin="local").to_props(),
    )
    sink.merge_node(
        "PayloadFamily",
        "key",
        PayloadFamily(key="prompt.generic", name="Prompt injection").to_props(),
    )
    return sink


def test_oracle_registry_materializes_reviewed_contract(tmp_path: Path) -> None:
    sink = _graph()
    registry = _write_registry(tmp_path)
    _commit_repository(tmp_path)
    stats = load_oracle_specs(sink, registry, tmp_path)
    assert stats == {"oracles": 1, "accepted": 1}
    signal = sink.get_node(
        "DetectionSignal", "key", "oracle_local_1_prompt_marker"
    )
    assert signal is not None
    assert signal["trustLevel"] == "accepted"
    assert signal["observableKind"] == "response"
    assert signal["successCriteria"] == (
        "Output contains the unique injected marker."
    )


def test_oracle_registry_rejects_source_hash_mismatch(tmp_path: Path) -> None:
    registry = _write_registry(
        tmp_path, source_hash=f"sha256:{'0' * 64}"
    )
    _commit_repository(tmp_path)
    with pytest.raises(OracleRegistryError, match="source_hash mismatch"):
        load_oracle_specs(
            _graph(),
            registry,
            tmp_path,
        )


def test_oracle_registry_rejects_dirty_source(tmp_path: Path) -> None:
    registry = _write_registry(tmp_path)
    _commit_repository(tmp_path)
    (tmp_path / "oracle-evidence.md").write_text(
        "Changed oracle criteria.\n",
        encoding="utf-8",
    )

    with pytest.raises(OracleRegistryError, match="differs from committed HEAD"):
        load_oracle_specs(_graph(), registry, tmp_path)
