"""Application entry point for snapshot-first structured CVE/GHSA ingestion."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from ckg.graph.ports import GraphRepository
from ckg.application.analyze_vulnerability import (
    AnalyzeVulnerabilityReport,
    GlobalMaintenanceReport,
    analyze_vulnerability_local,
    finalize_vulnerability_analysis,
    refresh_global_maintenance,
)
from ckg.ingestion.cve.importer import StructuredRecordImportReport, import_structured_records
from ckg.ingestion.cve.parser import parse_cve_services_record, parse_nvd_response
from ckg.ingestion.ghsa.importer import parse_ghsa_response
try:
    from ckg.provenance.store import SnapshotStore
except ImportError:
    from provenance.store import SnapshotStore


StructuredSourceKind = Literal["nvd", "cve_services", "ghsa"]


@dataclass(frozen=True)
class IngestStructuredRecordResult:
    snapshot_digest: str
    report: StructuredRecordImportReport
    analyses: tuple[AnalyzeVulnerabilityReport, ...] = ()
    global_maintenance: GlobalMaintenanceReport | None = None


def preview_structured_record_ids(*, source_kind: StructuredSourceKind, raw_payload: bytes) -> tuple[str, ...]:
    """Parse only enough to validate an API target before any graph write.

    The normal ingestion path still snapshots bytes before its authoritative
    parse/import operation.  This preflight is deliberately side-effect free:
    a request for ``/ingest/cve/CVE-X`` cannot accidentally import CVE-Y.
    """
    payload = json.loads(raw_payload)
    if source_kind == "nvd":
        records = parse_nvd_response(payload, source_url="preflight://request")
    elif source_kind == "cve_services":
        records = (parse_cve_services_record(payload, source_url="preflight://request"),)
    else:
        records = (parse_ghsa_response(payload, source_url="preflight://request"),)
    return tuple(record.record_id for record in records)


def ingest_structured_source(
    repository: GraphRepository,
    *,
    source_kind: StructuredSourceKind,
    raw_payload: bytes,
    source_url: str,
    retrieved_at: datetime,
    snapshot_root: str | Path,
    use_model: bool = False,
) -> IngestStructuredRecordResult:
    """Snapshot raw bytes before any parse; parser failures cannot lose evidence."""
    store = SnapshotStore(snapshot_root)
    digest = store.put(raw_payload)
    payload = json.loads(raw_payload)
    if source_kind == "nvd":
        records = parse_nvd_response(payload, source_url=source_url)
    elif source_kind == "cve_services":
        records = (parse_cve_services_record(payload, source_url=source_url),)
    else:
        records = (parse_ghsa_response(payload, source_url=source_url),)
    report = import_structured_records(
        repository,
        records,
        source_snapshot_digest=digest,
        retrieved_at=retrieved_at,
        snapshot_storage_uri=str(store.objects / digest.removeprefix("sha256:")),
    )
    # Import creates reported assertions first.  Enrichment is a separate
    # evidence-grounded pass so that any failure to extract/link facets cannot
    # invalidate or hide canonical source claims.
    analysis_ids = tuple(
        sorted(
            {
                record.record_id
                for record in records
                if record.record_id.startswith(("CVE-", "GHSA-"))
                and record.state.upper() not in {"REJECTED", "WITHDRAWN"}
            }
        )
    )
    local_analyses = tuple(
        analyze_vulnerability_local(
            repository,
            identifier,
            retrieved_at=retrieved_at,
            use_model=use_model,
        )
        for identifier in analysis_ids
    )
    # CWE profiles and co-occurrence are global derivations.  Recomputing them
    # per record makes NVD batches quadratic while producing the same final
    # state.  Keep each CVE's source-grounded enrichment local, then refresh
    # shared state exactly once after the complete batch is present.
    maintenance = refresh_global_maintenance(repository) if local_analyses else None
    analyses = tuple(
        finalize_vulnerability_analysis(analysis, maintenance)
        for analysis in local_analyses
    ) if maintenance else ()
    return IngestStructuredRecordResult(
        snapshot_digest=digest,
        report=report,
        analyses=analyses,
        global_maintenance=maintenance,
    )
