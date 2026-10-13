"""Canonical CWE import followed by isolated inferred-profile enrichment for new entries."""

from __future__ import annotations

from datetime import datetime

from ckg.evolution.new_cwe import NewCWEEnrichmentReport, enrich_new_cwes
from ckg.graph.ports import GraphRepository
from ckg.ingestion.cwe.importer import CWEImportReport, import_cwe_catalog
from ckg.ingestion.cwe.parser import parse_cwe_catalog
from ckg.ingestion.digests import verify_snapshot_digest


def ingest_cwe_catalog(repository: GraphRepository, *, raw_xml: bytes, source_snapshot_digest: str, retrieved_at: datetime, source_url: str) -> tuple[CWEImportReport, NewCWEEnrichmentReport]:
    verify_snapshot_digest(raw_xml, source_snapshot_digest)
    known = {node.node_id for node in repository.nodes("CWE")}
    catalog = parse_cwe_catalog(raw_xml, source_snapshot_digest=source_snapshot_digest, retrieved_at=retrieved_at, source_url=source_url)
    report = import_cwe_catalog(repository, catalog)
    added = tuple(weakness.cwe_id for weakness in catalog.weaknesses if weakness.cwe_id not in known)
    return report, enrich_new_cwes(repository, added)
