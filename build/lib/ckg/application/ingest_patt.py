"""Snapshot-first application use case for curated PATT payload references."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ckg.graph.ports import GraphRepository
from ckg.ingestion.patt.payload_importer import (
    PATTSourceFile,
    PATTStructuredImportReport,
    import_patt_payload_sources,
    slice_for_cwe,
)
from ckg.ingestion.patt.payload_index import PATTIndex
from ckg.provenance.store import SnapshotStore


def ingest_patt_sources(
    repository: GraphRepository,
    *,
    slice_cwe_id: str,
    sources: tuple[PATTSourceFile, ...],
    retrieved_at: datetime,
    snapshot_root: str | Path,
    max_payloads_per_family: int = 400,
) -> PATTStructuredImportReport:
    """Store exact source bytes before parsing and materializing one batch."""
    slice_for_cwe(slice_cwe_id)
    if not sources:
        raise ValueError("at least one PATT source is required")
    ordered = tuple(sorted(sources, key=lambda item: (item.source_file, item.source_url, item.kind)))
    for source in ordered:
        if not source.source_file.strip() or not source.source_url.strip():
            raise ValueError("PATT source_file and source_url are required")
        if not source.source_revision.strip():
            raise ValueError("PATT source_revision is required")
        if source.kind not in {"markdown", "wordlist"}:
            raise ValueError(f"unsupported PATT source kind: {source.kind!r}")
    store = SnapshotStore(snapshot_root)
    digests = tuple(store.put(source.content.encode("utf-8")) for source in ordered)
    return import_patt_payload_sources(
        repository,
        slice_cwe_id=slice_cwe_id,
        sources=ordered,
        snapshot_digests=digests,
        retrieved_at=retrieved_at,
        max_payloads_per_family=max_payloads_per_family,
        payload_index=PATTIndex(Path(snapshot_root) / "patt_payloads.sqlite3"),
    )
