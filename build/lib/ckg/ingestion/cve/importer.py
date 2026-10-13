"""Project structured source records into evidence-backed v2 graph assertions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from ckg.domain.entities.assertion import WeaknessAssertion
from ckg.domain.entities.cve import Vulnerability
from ckg.domain.entities.evidence import Evidence
from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.domain.value_objects.provenance import Provenance
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.ingestion.cve.models import AffectedProduct, StructuredVulnerabilityRecord
from ckg.provenance.graph_compaction import (
    affects_version_edge_id,
    compact_version_ranges,
    version_range_id,
)


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _source_record_id(record: StructuredVulnerabilityRecord, digest: str) -> str:
    return _stable_id("SRCREC", record.source_kind, record.record_id, digest)


def _primary_id(record: StructuredVulnerabilityRecord) -> str:
    identifiers = (record.record_id, *record.aliases)
    return next((item for item in identifiers if item.startswith("CVE-")), record.record_id)


def _vulnerability_label(identifier: str) -> str:
    return "GHSA" if identifier.startswith("GHSA-") else "CVE"


def _known_time(record: StructuredVulnerabilityRecord, fallback: datetime) -> datetime:
    return record.updated_at or record.published_at or fallback


def _is_withdrawn_or_rejected(state: str) -> bool:
    return state.upper() in {"REJECTED", "WITHDRAWN"}


def _product_id(product: AffectedProduct) -> str:
    return _stable_id("PRODUCT", product.vendor or "", product.product or "", product.package_name or "", product.ecosystem or "")


@dataclass(frozen=True)
class StructuredRecordImportReport:
    source_record_count: int
    vulnerability_count: int
    evidence_count: int
    weakness_assertion_count: int
    alias_count: int
    affected_product_count: int
    version_range_count: int
    unresolved_cwe_ids: tuple[str, ...]
    suppressed_record_ids: tuple[str, ...]


def import_structured_records(
    repository: GraphRepository,
    records: tuple[StructuredVulnerabilityRecord, ...],
    *,
    source_snapshot_digest: str,
    retrieved_at: datetime,
    snapshot_storage_uri: str | None = None,
) -> StructuredRecordImportReport:
    """Import a source batch. Every reported CWE remains its own assertion.

    ``source_snapshot_digest`` identifies immutable raw source bytes supplied by
    the caller.  It is intentionally shared by spans from the same fetch batch;
    their JSON pointers identify the individual source record and mapping.
    """
    existing_nodes = {node.node_id: node for node in repository.nodes()}
    cwe_ids = {node.node_id for node in repository.nodes("CWE")}
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    new_ids: set[str] = set()
    unresolved: set[str] = set()
    suppressed: set[str] = set()
    evidence_count = 0
    assertion_count = 0
    alias_count = 0
    product_ids: set[str] = set()
    range_ids: set[str] = set()
    projection_nodes: list[GraphNode] = []
    existing_source_records = {
        node.node_id: node for node in repository.nodes("VulnerabilitySourceRecord")
    }
    described_targets = {
        edge.subject_id: edge.object_id for edge in repository.edges("DESCRIBES")
    }

    def source_time(node: GraphNode) -> str:
        return str(node.props.get("known_at") or node.props.get("updated_at") or node.props.get("published_at") or "")

    def mark_source_assertions_stale(source_ids: set[str]) -> None:
        for node in existing_nodes.values():
            provenance = node.props.get("provenance")
            source_id = provenance.get("source_id") if isinstance(provenance, dict) else None
            if source_id in source_ids and node.label in {"WeaknessAssertion", "TechniqueAssertion", "ContextAssertion"}:
                projection_nodes.append(GraphNode(label=node.label, node_id=node.node_id, props={**node.props, "stale": True}))

    def add_node(node: GraphNode) -> None:
        if node.node_id not in existing_nodes and node.node_id not in new_ids:
            nodes.append(node)
            new_ids.add(node.node_id)

    for record_index, record in enumerate(records):
        primary_id = _primary_id(record)
        known_at = _known_time(record, retrieved_at)
        matching_prior = [
            node for source_id, node in existing_source_records.items()
            if described_targets.get(source_id) == primary_id
            and node.props.get("source_kind") == record.source_kind
            and node.props.get("record_id") == record.record_id
        ]
        prior_latest = max(matching_prior, key=source_time, default=None)
        is_current = prior_latest is None or known_at.isoformat() >= source_time(prior_latest)
        if primary_id not in existing_nodes and primary_id not in new_ids:
            vulnerability = Vulnerability(
                vulnerability_id=primary_id,
                title=record.title or record.record_id,
                description=record.description,
                published_at=record.published_at or known_at,
                aliases=tuple(sorted(set((record.record_id, *record.aliases)) - {primary_id})),
            )
            add_node(
                GraphNode(
                    label=_vulnerability_label(primary_id),
                    node_id=primary_id,
                    props=vulnerability.model_dump(mode="json", exclude_none=True),
                )
            )
        source_record_id = _source_record_id(record, source_snapshot_digest)
        evidence_id = _stable_id("EVID-structured", record.source_kind, record.record_id, source_snapshot_digest)
        evidence = Evidence(
            evidence_id=evidence_id,
            kind=f"{record.source_kind}_record",
            content_digest=source_snapshot_digest,
            retrieved_at=retrieved_at,
            source_url=record.source_url,
            storage_uri=snapshot_storage_uri,
        )
        add_node(
            GraphNode(
                label="Evidence",
                node_id=evidence_id,
                props={
                    **evidence.model_dump(mode="json", exclude_none=True),
                    "source_record_id": record.record_id,
                    "source_state": record.state,
                    "source_revision": record.source_revision,
                },
            )
        )
        evidence_count += 1
        add_node(
            GraphNode(
                label="VulnerabilitySourceRecord",
                node_id=source_record_id,
                props={
                    "record_id": record.record_id,
                    "source_kind": record.source_kind,
                    "source_url": record.source_url,
                    "source_revision": record.source_revision,
                    "state": record.state,
                    # Extraction must consume this exact revision, rather than
                    # the mutable stable CVE projection.
                    "title": record.title,
                    "description": record.description,
                    "published_at": record.published_at.isoformat() if record.published_at else None,
                    "updated_at": record.updated_at.isoformat() if record.updated_at else None,
                    "known_at": known_at.isoformat(),
                    "snapshot_digest": source_snapshot_digest,
                    "record_index": record_index,
                },
            )
        )
        edges.extend(
            (
                GraphEdge(edge_id=_stable_id("EDGE-DESCRIBES", source_record_id, primary_id), edge_type="DESCRIBES", subject_id=source_record_id, object_id=primary_id),
                GraphEdge(edge_id=_stable_id("EDGE-SOURCE-RECORD-EVIDENCE", source_record_id, evidence_id), edge_type="SUPPORTED_BY", subject_id=source_record_id, object_id=evidence_id),
                GraphEdge(edge_id=_stable_id("EDGE-VULNERABILITY-EVIDENCE", primary_id, evidence_id), edge_type="SUPPORTED_BY", subject_id=primary_id, object_id=evidence_id, props={"source_record_id": source_record_id}),
            )
        )
        if is_current:
            vulnerability = Vulnerability(
                vulnerability_id=primary_id,
                title=record.title or record.record_id,
                description=record.description,
                published_at=record.published_at or known_at,
                aliases=tuple(sorted(set((record.record_id, *record.aliases)) - {primary_id})),
            )
            projection_nodes.append(
                GraphNode(
                    label=_vulnerability_label(primary_id),
                    node_id=primary_id,
                    props={
                        **vulnerability.model_dump(mode="json", exclude_none=True),
                        "current_source_record_id": source_record_id,
                        "current_source_kind": record.source_kind,
                        "current_source_state": record.state,
                    },
                )
            )
            mark_source_assertions_stale({node.node_id for node in matching_prior})
        for alias in sorted(set((record.record_id, *record.aliases)) - {primary_id}):
            if not alias.startswith(("CVE-", "GHSA-")):
                continue
            add_node(
                GraphNode(
                    label=_vulnerability_label(alias),
                    node_id=alias,
                    props={"vulnerability_id": alias, "alias_only": True},
                )
            )
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("EDGE-ALIAS-OF", alias, primary_id, source_record_id),
                    edge_type="ALIAS_OF",
                    subject_id=alias,
                    object_id=primary_id,
                    props={"source_record_id": source_record_id, "evidence_id": evidence_id},
                )
            )
            alias_count += 1
        for affected_index, affected in enumerate(record.affected):
            if not any((affected.product, affected.package_name)):
                continue
            product_id = _product_id(affected)
            product_ids.add(product_id)
            add_node(
                GraphNode(
                    label="Product",
                    node_id=product_id,
                    props={
                        "vendor": affected.vendor,
                        "name": affected.product,
                        "package_name": affected.package_name,
                        "ecosystem": affected.ecosystem,
                        "cpe_uri": affected.cpe_uri,
                        "aliases": sorted(
                            {
                                *affected.aliases,
                                *(
                                    [f"{affected.vendor}/{affected.product}"]
                                    if affected.vendor and affected.product
                                    else []
                                ),
                            }
                        ),
                        "source_pointer": affected.source_pointer,
                    },
                )
            )
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("EDGE-AFFECTS", primary_id, product_id, source_record_id),
                    edge_type="AFFECTS",
                    subject_id=primary_id,
                    object_id=product_id,
                    props={
                        "source_record_id": source_record_id,
                        "affected_index": affected_index,
                        "source_pointer": affected.source_pointer,
                    },
                )
            )
            for version in affected.versions:
                version_id = version_range_id(
                    affected.ecosystem or "unknown", version.expression, version.status
                )
                range_ids.add(version_id)
                add_node(
                    GraphNode(
                        label="VersionRange",
                        node_id=version_id,
                        props={
                            "ecosystem": affected.ecosystem or "unknown",
                            "expression": version.expression,
                            "status": version.status,
                        },
                    )
                )
                edges.append(
                    GraphEdge(
                        edge_id=affects_version_edge_id(primary_id, version_id, source_record_id),
                        edge_type="AFFECTS_VERSION",
                        subject_id=primary_id,
                        object_id=version_id,
                        props={
                            "source_record_id": source_record_id,
                            "product_id": product_id,
                            "source_pointer": affected.source_pointer,
                        },
                    )
                )
        if _is_withdrawn_or_rejected(record.state):
            suppressed.add(record.record_id)
            continue
        for weakness in record.weaknesses:
            if weakness.cwe_id not in cwe_ids:
                unresolved.add(weakness.cwe_id)
                continue
            assertion_id = _stable_id("WAS-REPORTED", primary_id, weakness.cwe_id, source_record_id, weakness.json_pointer)
            assertion = WeaknessAssertion(
                assertion_id=assertion_id,
                vulnerability_id=primary_id,
                cwe_id=weakness.cwe_id,
                status=FactStatus.REPORTED,
                provenance=Provenance(
                    source_id=source_record_id,
                    source_kind=record.source_kind,
                    source_url=record.source_url,
                    source_release=record.source_revision,
                    retrieved_at=retrieved_at,
                ),
                evidence_spans=(EvidenceSpan(evidence_id=evidence_id, content_digest=source_snapshot_digest, locator=weakness.json_pointer),),
                role="reported",
            )
            add_node(GraphNode(label="WeaknessAssertion", node_id=assertion_id, props=assertion.model_dump(mode="json", exclude_none=True)))
            edges.extend(
                (
                    GraphEdge(edge_id=_stable_id("EDGE-HAS-WEAKNESS-ASSERTION", primary_id, assertion_id), edge_type="HAS_WEAKNESS_ASSERTION", subject_id=primary_id, object_id=assertion_id, props={"source_record_id": source_record_id}),
                    GraphEdge(edge_id=_stable_id("EDGE-MAPS-TO", assertion_id, weakness.cwe_id), edge_type="MAPS_TO", subject_id=assertion_id, object_id=weakness.cwe_id, props={"source_record_id": source_record_id}),
                )
            )
            assertion_count += 1
    # A newly observed vulnerability has both a base identity node and its
    # current-source projection in this same import. In-memory storage used to
    # overwrite the first silently, while Neo4j correctly rejected the batch
    # as ambiguous. Collapse by stable identity here, with the later projection
    # deliberately winning because it contains the complete current-source
    # metadata. Different labels for one identity remain a hard error.
    write_nodes: dict[str, GraphNode] = {}
    for node in (*nodes, *projection_nodes):
        existing = write_nodes.get(node.node_id)
        if existing is not None and existing.label != node.label:
            raise ValueError(f"node identity collision: {node.node_id}")
        write_nodes[node.node_id] = node
    # A source can list the same product more than once, each time with a
    # different range or pointer. Preserve every observation under the one
    # stable AFFECTS identity, including observations from an earlier ingest.
    affects_by_id: dict[str, list[GraphEdge]] = {}
    for edge in edges:
        if edge.edge_type == "AFFECTS":
            affects_by_id.setdefault(edge.edge_id, []).append(edge)
    prior_affects = {edge.edge_id: edge for edge in repository.edges("AFFECTS")}
    for edge_id, group in affects_by_id.items():
        prior = prior_affects.get(edge_id)
        if prior is not None:
            group.insert(0, prior)
    normalized_affects: list[GraphEdge] = []
    for edge_id, group in sorted(affects_by_id.items()):
        observations: dict[str, dict[str, object]] = {}
        for edge in group:
            stored = edge.props.get("affected_observations")
            items = stored if isinstance(stored, list) else [
                {"affected_index": edge.props.get("affected_index"),
                 "source_pointer": edge.props.get("source_pointer")}
            ]
            for item in items:
                if isinstance(item, dict):
                    observations[json.dumps(item, sort_keys=True)] = item
        first = group[0]
        ordered = [observations[key] for key in sorted(observations)]
        normalized_affects.append(GraphEdge(
            edge_id=edge_id, edge_type="AFFECTS",
            subject_id=first.subject_id, object_id=first.object_id,
            props={
                **first.props,
                "affected_observations": ordered,
                "affected_indices": sorted({item["affected_index"] for item in ordered if isinstance(item.get("affected_index"), int)}),
                "source_pointers": sorted({item["source_pointer"] for item in ordered if isinstance(item.get("source_pointer"), str)}),
            },
        ))
    edges = [edge for edge in edges if edge.edge_type != "AFFECTS"] + normalized_affects

    # Existing version associations must participate in the same compaction
    # as new observations. Otherwise the stable edge ID would be overwritten
    # with only the newest product's metadata by atomic_write.
    new_version_edges = [edge for edge in edges if edge.edge_type == "AFFECTS_VERSION"]
    touched_keys = {
        (edge.subject_id, edge.object_id, edge.props.get("source_record_id"))
        for edge in new_version_edges
    }
    for prior in repository.edges("AFFECTS_VERSION"):
        old_range = existing_nodes.get(prior.object_id)
        if old_range is None or old_range.label != "VersionRange":
            continue
        key = (
            prior.subject_id,
            version_range_id(
                str(old_range.props.get("ecosystem", "")),
                str(old_range.props.get("expression", "")),
                str(old_range.props.get("status", "")),
            ),
            prior.props.get("source_record_id"),
        )
        if key in touched_keys:
            edges.append(prior)
    # Existing shared values are valid edge endpoints, but add_node correctly
    # omits them from the write batch. Include them for compaction's semantic
    # lookup, then keep them out of the write to retain stored provenance.
    existing_ranges = [
        existing_nodes[edge.object_id]
        for edge in edges
        if edge.edge_type == "AFFECTS_VERSION"
        and edge.object_id not in write_nodes
        and edge.object_id in existing_nodes
    ]
    existing_ranges = list({node.node_id: node for node in existing_ranges}.values())
    compacted_nodes, compacted_edges, _ = compact_version_ranges(
        (*write_nodes.values(), *existing_ranges), edges
    )
    repository.atomic_write(
        nodes=[node for node in compacted_nodes if node.node_id in write_nodes],
        edges=compacted_edges,
    )
    return StructuredRecordImportReport(
        source_record_count=len(records),
        vulnerability_count=len({ _primary_id(record) for record in records }),
        evidence_count=evidence_count,
        weakness_assertion_count=assertion_count,
        alias_count=alias_count,
        affected_product_count=len(product_ids),
        version_range_count=len(range_ids),
        unresolved_cwe_ids=tuple(sorted(unresolved)),
        suppressed_record_ids=tuple(sorted(suppressed)),
    )
