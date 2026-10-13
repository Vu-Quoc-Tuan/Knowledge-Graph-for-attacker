"""Build the canonical CWE/CAPEC foundation from already pinned source bytes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ckg.graph.ports import GraphRepository
from ckg.ingestion.capec.importer import CAPECImportReport, import_capec_catalog
from ckg.ingestion.capec.parser import parse_capec_catalog
from ckg.ingestion.cwe.importer import CWEImportReport, import_cwe_catalog
from ckg.ingestion.cwe.parser import parse_cwe_catalog
from ckg.ingestion.digests import verify_snapshot_digest


@dataclass(frozen=True)
class InitialGraphBuildReport:
    cwe: CWEImportReport
    capec: CAPECImportReport


def build_initial_graph(
    repository: GraphRepository,
    *,
    cwe_xml: bytes,
    cwe_snapshot_digest: str,
    cwe_retrieved_at: datetime,
    cwe_source_url: str,
    capec_xml: bytes,
    capec_snapshot_digest: str,
    capec_retrieved_at: datetime,
    capec_source_url: str,
) -> InitialGraphBuildReport:
    """Import canonical data only; no CVE, LLM, or learned-edge writer runs here."""
    verify_snapshot_digest(cwe_xml, cwe_snapshot_digest)
    verify_snapshot_digest(capec_xml, capec_snapshot_digest)
    cwe = parse_cwe_catalog(
        cwe_xml,
        source_snapshot_digest=cwe_snapshot_digest,
        retrieved_at=cwe_retrieved_at,
        source_url=cwe_source_url,
    )
    capec = parse_capec_catalog(
        capec_xml,
        source_snapshot_digest=capec_snapshot_digest,
        retrieved_at=capec_retrieved_at,
        source_url=capec_source_url,
    )
    return InitialGraphBuildReport(
        cwe=import_cwe_catalog(repository, cwe),
        capec=import_capec_catalog(repository, capec),
    )
