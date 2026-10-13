"""Canonical graph materialization for PATT reference payloads.

This module deliberately materializes source-backed *references*, not
executable test material.  Validation and target binding stay in the separate
proposal/receipt workflow.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.ingestion.patt.payload_extractor import (
    PayloadCandidate,
    PayloadExtractionReport,
    extract_payload_candidates,
    extract_wordlist_candidates,
)
from ckg.ingestion.patt.payload_index import PATTIndex, payload_digest
from ckg.ingestion.patt.slices import SLICES, VulnSlice


PATTSourceKind = Literal["markdown", "wordlist"]


def _stable_id(prefix: str, *parts: str) -> str:
    material = chr(31).join(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:24]}"


@dataclass(frozen=True)
class PATTSourceFile:
    source_file: str
    source_url: str
    source_revision: str
    content: str
    kind: PATTSourceKind = "markdown"
    technology: str | None = None


@dataclass(frozen=True)
class PATTStructuredImportReport:
    slice_cwe_id: str
    document_count: int
    payload_count: int
    family_count: int
    technology_count: int
    skipped_over_cap: int
    unclassified_table_spans: int
    headings_without_payloads: tuple[str, ...]
    snapshot_digests: tuple[str, ...]


def slice_for_cwe(cwe_id: str) -> VulnSlice:
    for slice_ in SLICES:
        if slice_.weakness_id == cwe_id:
            return slice_
    raise ValueError(f"unknown PATT slice for {cwe_id}")


def _family_by_key(slice_: VulnSlice) -> dict[str, object]:
    result = {family.key: family for family in slice_.families}
    if slice_.intruder_family is not None:
        result[slice_.intruder_family.key] = slice_.intruder_family
    return result


def _extract(
    source: PATTSourceFile,
    *,
    slice_: VulnSlice,
    max_payloads_per_family: int,
) -> PayloadExtractionReport:
    if source.kind == "markdown":
        return extract_payload_candidates(
            slice_,
            source_file=source.source_file,
            source_url=source.source_url,
            markdown=source.content,
            technology=source.technology,
            max_payloads_per_family=max_payloads_per_family,
        )
    if source.kind == "wordlist":
        if slice_.intruder_family is None:
            raise ValueError(f"PATT slice {slice_.weakness_id} has no Intruder family")
        return extract_wordlist_candidates(
            slice_,
            source_file=source.source_file,
            source_url=source.source_url,
            wordlist=source.content,
            technology=source.technology,
            max_payloads_per_family=max_payloads_per_family,
        )
    raise ValueError(f"unsupported PATT source kind: {source.kind!r}")


def import_patt_payload_sources(
    repository: GraphRepository,
    *,
    slice_cwe_id: str,
    sources: tuple[PATTSourceFile, ...],
    snapshot_digests: tuple[str, ...],
    retrieved_at: datetime,
    max_payloads_per_family: int = 400,
    payload_index: PATTIndex | None = None,
) -> PATTStructuredImportReport:
    """Materialize compact graph context and index exact payload references.

    The graph intentionally contains no one-node-per-payload or
    one-node-per-section expansion.  Those records remain queryable through
    ``payload_index`` with their immutable snapshot locator.
    """
    if len(sources) != len(snapshot_digests):
        raise ValueError("each PATT source requires exactly one snapshot digest")
    if max_payloads_per_family < 0:
        raise ValueError("max_payloads_per_family must be non-negative")
    if slice_cwe_id not in {node.node_id for node in repository.nodes("CWE")}:
        raise ValueError(f"CWE must exist before PATT payload import: {slice_cwe_id}")
    slice_ = slice_for_cwe(slice_cwe_id)
    families = _family_by_key(slice_)

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    family_ids: dict[str, str] = {}
    technology_ids: dict[str, str] = {}
    seen_evidence: set[str] = set()
    seen_documents: set[str] = set()
    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    seen_payload_ids: set[str] = set()
    payload_records: list[dict[str, object]] = []
    payload_count = 0
    skipped_over_cap = 0
    unclassified_table_spans = 0
    headings_without_payloads: list[str] = []

    for source, digest in zip(sources, snapshot_digests, strict=True):
        document_id = _stable_id(
            "PATT-DOCUMENT", slice_cwe_id, source.source_file,
            source.source_url, source.source_revision, source.kind, digest,
        )
        evidence_id = _stable_id("EVID-PATT-PAYLOAD", document_id, digest)
        if document_id not in seen_documents:
            document = GraphNode(
                label="PATTDocument", node_id=document_id,
                props={
                    "document_id": document_id,
                    "slice_cwe_id": slice_cwe_id,
                    "source_file": source.source_file,
                    "source_url": source.source_url,
                    "source_revision": source.source_revision,
                    "source_kind": source.kind,
                    "source_snapshot_digest": digest,
                    "retrieved_at": retrieved_at.isoformat(),
                },
            )
            nodes.append(document)
            node_ids.add(document_id)
            seen_documents.add(document_id)
        if evidence_id not in seen_evidence:
            evidence = GraphNode(
                label="Evidence", node_id=evidence_id,
                props={
                    "evidence_id": evidence_id,
                    "kind": f"patt_{source.kind}",
                    "content_digest": digest,
                    "retrieved_at": retrieved_at.isoformat(),
                    "source_url": source.source_url,
                    "storage_uri": None,
                    "source_revision": source.source_revision,
                },
            )
            nodes.append(evidence)
            node_ids.add(evidence_id)
            seen_evidence.add(evidence_id)
        document_edge = GraphEdge(
            edge_id=_stable_id("EDGE-PATT-DOCUMENT-SUPPORTED-BY", document_id, evidence_id),
            edge_type="SUPPORTED_BY",
            subject_id=document_id,
            object_id=evidence_id,
            props={"source_snapshot_digest": digest},
        )
        if document_edge.edge_id not in edge_ids:
            edges.append(document_edge)
            edge_ids.add(document_edge.edge_id)

        report = _extract(
            source, slice_=slice_, max_payloads_per_family=max_payloads_per_family
        )
        skipped_over_cap += report.skipped_over_cap
        unclassified_table_spans += report.unclassified_table_spans
        for heading in report.headings_without_payloads:
            qualified = f"{source.source_file}:{heading}"
            if qualified not in headings_without_payloads:
                headings_without_payloads.append(qualified)

        for candidate in report.candidates:
            family = families[candidate.family_key]
            family_id = family_ids.setdefault(
                candidate.family_key,
                _stable_id("PATT-PAYLOAD-FAMILY", slice_cwe_id, candidate.family_key),
            )
            if family_id not in node_ids:
                nodes.append(GraphNode(
                    label="PayloadFamily", node_id=family_id,
                    props={
                        "family_key": candidate.family_key,
                        "name": family.name,
                        "detection_signal": family.detection_signal,
                        "slice_cwe_id": slice_cwe_id,
                        "origin": "patt",
                        "curation_status": "upstream_curated",
                    },
                ))
                node_ids.add(family_id)
                family_edge = GraphEdge(
                    edge_id=_stable_id("EDGE-HAS-PAYLOAD-FAMILY", slice_cwe_id, family_id),
                    edge_type="HAS_PAYLOAD_FAMILY",
                    subject_id=slice_cwe_id,
                    object_id=family_id,
                    props={"source": "patt"},
                )
                if family_edge.edge_id not in edge_ids:
                    edges.append(family_edge)
                    edge_ids.add(family_edge.edge_id)

            payload_id = _stable_id(
                "PATT-PAYLOAD", family_id, candidate.value,
                candidate.technology or "", digest, candidate.locator,
            )
            if payload_id in seen_payload_ids:
                continue
            seen_payload_ids.add(payload_id)
            payload_records.append({
                "payload_id": payload_id,
                "cwe_id": slice_cwe_id,
                "value": candidate.value,
                "payload_digest": payload_digest(candidate.value),
                "family_key": candidate.family_key,
                "family_name": candidate.family_name,
                "technology": candidate.technology,
                "source_file": source.source_file,
                "source_url": source.source_url,
                "source_revision": source.source_revision,
                "source_kind": source.kind,
                "source_snapshot_digest": digest,
                "section_heading": candidate.section_heading,
                "locator": candidate.locator,
                "extraction": candidate.extraction,
                "origin": "patt",
                "curation_status": "upstream_curated",
                "validation_status": "untested",
            })
            source_family_edge = GraphEdge(
                edge_id=_stable_id("EDGE-PATT-FAMILY-SOURCED-FROM", family_id, document_id),
                edge_type="SOURCED_FROM",
                subject_id=family_id,
                object_id=document_id,
                props={"source_snapshot_digest": digest},
            )
            if source_family_edge.edge_id not in edge_ids:
                edges.append(source_family_edge)
                edge_ids.add(source_family_edge.edge_id)
            if candidate.technology:
                technology_id = technology_ids.setdefault(
                    candidate.technology,
                    _stable_id("PATT-TECHNOLOGY", candidate.technology.casefold()),
                )
                if technology_id not in node_ids:
                    nodes.append(GraphNode(
                        label="Technology", node_id=technology_id,
                        props={"name": candidate.technology, "origin": "patt"},
                    ))
                    node_ids.add(technology_id)
                family_technology_edge = GraphEdge(
                    edge_id=_stable_id("EDGE-FAMILY-APPLIES-TO", family_id, technology_id),
                    edge_type="APPLIES_TO", subject_id=family_id, object_id=technology_id,
                )
                if family_technology_edge.edge_id not in edge_ids:
                    edges.append(family_technology_edge)
                    edge_ids.add(family_technology_edge.edge_id)
            payload_count += 1

    if payload_index is not None:
        payload_index.put_many(payload_records)
    repository.atomic_write(nodes=nodes, edges=edges)
    return PATTStructuredImportReport(
        slice_cwe_id=slice_cwe_id,
        document_count=len(seen_documents),
        payload_count=payload_count,
        family_count=len(family_ids),
        technology_count=len(technology_ids),
        skipped_over_cap=skipped_over_cap,
        unclassified_table_spans=unclassified_table_spans,
        headings_without_payloads=tuple(headings_without_payloads),
        snapshot_digests=tuple(snapshot_digests),
    )


__all__ = [
    "PATTSourceFile",
    "PATTSourceKind",
    "PATTStructuredImportReport",
    "import_patt_payload_sources",
    "slice_for_cwe",
]
