"""Migrate the legacy vulnerability registry without reviving direct CVE-to-CWE edges.

The legacy registry is useful historical input, but its ``epistemic_status``
does not use the v2 status vocabulary and a registry entry is not MITRE
canonical knowledge.  This adapter deliberately preserves the old status as
metadata while materializing a ``WeaknessAssertion`` with explicit evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ckg.domain.entities.assertion import WeaknessAssertion
from ckg.domain.entities.cve import Vulnerability
from ckg.domain.entities.evidence import Evidence
from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.domain.value_objects.provenance import Provenance
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def _legacy_status(legacy_status: str, *, all_snapshots_available: bool) -> FactStatus:
    """Map legacy labels conservatively; legacy ``canonical`` is never CANONICAL."""
    if legacy_status == "inferred":
        return FactStatus.INFERRED
    if legacy_status == "observed":
        return FactStatus.OBSERVED
    if legacy_status == "validated" and all_snapshots_available:
        return FactStatus.VALIDATED
    return FactStatus.REPORTED


@dataclass(frozen=True)
class LegacyRegistryMigrationReport:
    target_schema: str
    vulnerability_count: int
    evidence_count: int
    weakness_assertion_count: int
    product_count: int
    component_count: int
    version_range_count: int
    unresolved_cwe_ids: tuple[str, ...]
    missing_snapshot_evidence_ids: tuple[str, ...]
    skipped_assertion_vulnerability_ids: tuple[str, ...]
    diagnostics: tuple[tuple[str, str, str], ...] = ()


def migrate_legacy_vulnerability_registry(
    repository: GraphRepository,
    registry_path: str | Path,
    *,
    snapshot_object_dir: str | Path | None = None,
) -> LegacyRegistryMigrationReport:
    """Materialize registry records as v2 entities and reified assertions.

    The existing ``ingest.vulnerability_loader`` parser remains the strict
    reader for the source file.  No legacy graph nodes or relationships are
    read or written here, which makes the migration repeatable and prevents
    ``INSTANCE_OF`` from becoming a second source of truth.
    """
    from ingest.vulnerability_loader import read_vulnerability_registry

    registry = read_vulnerability_registry(Path(registry_path))
    canonical_cwe_ids = {node.node_id for node in repository.nodes("CWE")}
    object_dir = Path(snapshot_object_dir) if snapshot_object_dir is not None else None

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    known_nodes: set[str] = set()
    unresolved_cwes: set[str] = set()
    missing_snapshots: set[str] = set()
    skipped_assertions: set[str] = set()
    diagnostics: set[tuple[str, str, str]] = set()
    evidence_count = 0
    assertion_count = 0
    products: set[str] = set()
    components: set[str] = set()
    ranges: set[str] = set()

    def add_node(node: GraphNode) -> None:
        if node.node_id not in known_nodes:
            nodes.append(node)
            known_nodes.add(node.node_id)

    for entry_index, entry in enumerate(registry.vulnerabilities):
        published_at = _parse_timestamp(entry.published_at)
        vulnerability = Vulnerability(
            vulnerability_id=entry.vuln_id,
            title=entry.title,
            description=entry.description or None,
            published_at=published_at,
            version_ranges=(),
        )
        vuln_label = "GHSA" if entry.vuln_id.startswith("GHSA-") else "CVE"
        add_node(
            GraphNode(
                label=vuln_label,
                node_id=entry.vuln_id,
                props={
                    **vulnerability.model_dump(mode="json", exclude_none=True),
                    "target_schema": "ckg-v2",
                    "legacy_registry_status": entry.epistemic_status,
                    "legacy_registry_schema_version": registry.schema_version,
                    "legacy_registry_entry": entry_index,
                },
            )
        )

        if entry.product is not None:
            product_id = f"PRODUCT:{entry.product.vendor or 'unknown'}:{entry.product.name}"
            add_node(
                GraphNode(
                    label="Product",
                    node_id=product_id,
                    props={"name": entry.product.name, "vendor": entry.product.vendor},
                )
            )
            products.add(product_id)
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("EDGE-AFFECTS", entry.vuln_id, product_id),
                    edge_type="AFFECTS",
                    subject_id=entry.vuln_id,
                    object_id=product_id,
                    props={"source": "legacy-vulnerability-registry", "known_at": entry.published_at},
                )
            )
        else:
            product_id = None

        if entry.component is not None:
            component_id = f"COMPONENT:{product_id or 'unknown'}:{entry.component.name}"
            add_node(
                GraphNode(
                    label="Component",
                    node_id=component_id,
                    props={"name": entry.component.name, "path": entry.component.path},
                )
            )
            components.add(component_id)
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("EDGE-AFFECTS-COMPONENT", entry.vuln_id, component_id),
                    edge_type="AFFECTS_COMPONENT",
                    subject_id=entry.vuln_id,
                    object_id=component_id,
                    props={"source": "legacy-vulnerability-registry", "known_at": entry.published_at},
                )
            )
            if product_id is not None:
                edges.append(
                    GraphEdge(
                        edge_id=_stable_id("EDGE-PART-OF", component_id, product_id),
                        edge_type="PART_OF",
                        subject_id=component_id,
                        object_id=product_id,
                        props={"source": "legacy-vulnerability-registry"},
                    )
                )

        for version_range in entry.version_ranges:
            range_id = _stable_id("VERSION-RANGE", product_id or "unknown", version_range.spec, version_range.status)
            add_node(
                GraphNode(
                    label="VersionRange",
                    node_id=range_id,
                    props={
                        "ecosystem": entry.product.name if entry.product else "unknown",
                        "expression": version_range.spec,
                        "status": version_range.status,
                    },
                )
            )
            ranges.add(range_id)
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("EDGE-AFFECTS-VERSION", entry.vuln_id, range_id),
                    edge_type="AFFECTS_VERSION",
                    subject_id=entry.vuln_id,
                    object_id=range_id,
                    props={"status": version_range.status, "known_at": entry.published_at},
                )
            )

        spans: list[EvidenceSpan] = []
        entry_snapshots_available = bool(entry.evidence)
        for evidence_index, legacy_evidence in enumerate(entry.evidence):
            evidence_id = f"EVID-legacy-{legacy_evidence.evidence_id.removeprefix('EVD-')}"
            object_path = (
                object_dir / legacy_evidence.source_hash.removeprefix("sha256:")
                if object_dir is not None
                else None
            )
            snapshot_available = object_path is not None and object_path.is_file()
            entry_snapshots_available = entry_snapshots_available and snapshot_available
            if not snapshot_available:
                missing_snapshots.add(evidence_id)
                diagnostics.add(
                    (
                        "MISSING_SNAPSHOT_ARTIFACT",
                        evidence_id,
                        "legacy evidence points to a snapshot object that is not present locally",
                    )
                )
            retrieved_at = _parse_timestamp(legacy_evidence.observed_at or entry.observed_at or entry.published_at)
            evidence = Evidence(
                evidence_id=evidence_id,
                kind=legacy_evidence.kind,
                content_digest=legacy_evidence.source_hash,
                retrieved_at=retrieved_at,
                source_url=legacy_evidence.source_ref,
                storage_uri=str(object_path) if snapshot_available else None,
            )
            add_node(
                GraphNode(
                    label="Evidence",
                    node_id=evidence_id,
                    props={
                        **evidence.model_dump(mode="json", exclude_none=True),
                        "target_schema": "ckg-v2",
                        "excerpt": legacy_evidence.excerpt,
                        "legacy_evidence_id": legacy_evidence.evidence_id,
                        "source_snapshot_available": snapshot_available,
                        "legacy_registry_entry": entry_index,
                        "legacy_evidence_entry": evidence_index,
                    },
                )
            )
            evidence_count += 1
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("EDGE-SUPPORTED-BY", entry.vuln_id, evidence_id),
                    edge_type="SUPPORTED_BY",
                    subject_id=entry.vuln_id,
                    object_id=evidence_id,
                    props={"source": "legacy-vulnerability-registry", "known_at": entry.published_at},
                )
            )
            spans.append(
                EvidenceSpan(
                    evidence_id=evidence_id,
                    content_digest=legacy_evidence.source_hash,
                    locator=f"legacy-registry:/vulnerabilities/{entry_index}/evidence/{evidence_index}",
                    excerpt=legacy_evidence.excerpt,
                )
            )

        if entry.cwe_id is None or not spans:
            if entry.cwe_id is not None:
                skipped_assertions.add(entry.vuln_id)
            if entry.cwe_id is not None and not spans:
                diagnostics.add(
                    (
                        "MISSING_EVIDENCE_SPAN",
                        entry.vuln_id,
                        "legacy CWE claim has no source evidence span",
                    )
                )
            continue
        if entry.cwe_id not in canonical_cwe_ids:
            unresolved_cwes.add(entry.cwe_id)
            skipped_assertions.add(entry.vuln_id)
            diagnostics.add(
                (
                    "UNRESOLVED_CWE_TARGET",
                    entry.vuln_id,
                    f"CWE target {entry.cwe_id} is not present in the canonical catalog",
                )
            )
            continue

        assertion_id = _stable_id("WAS-LEGACY", entry.vuln_id, entry.cwe_id)
        assertion = WeaknessAssertion(
            assertion_id=assertion_id,
            vulnerability_id=entry.vuln_id,
            cwe_id=entry.cwe_id,
            status=_legacy_status(entry.epistemic_status, all_snapshots_available=entry_snapshots_available),
            provenance=Provenance(
                source_id="LEGACY-VULNERABILITY-REGISTRY-v1",
                source_kind="legacy_vulnerability_registry",
                source_url=str(Path(registry_path)),
                retrieved_at=_parse_timestamp(entry.observed_at or entry.published_at),
            ),
            evidence_spans=tuple(spans),
            role="legacy-reported",
        )
        add_node(
            GraphNode(
                label="WeaknessAssertion",
                node_id=assertion_id,
                props={
                    **assertion.model_dump(mode="json", exclude_none=True),
                    "target_schema": "ckg-v2",
                    "legacy_registry_status": entry.epistemic_status,
                    "all_source_snapshots_available": entry_snapshots_available,
                },
            )
        )
        edges.extend(
            (
                GraphEdge(
                    edge_id=_stable_id("EDGE-HAS-WEAKNESS-ASSERTION", entry.vuln_id, assertion_id),
                    edge_type="HAS_WEAKNESS_ASSERTION",
                    subject_id=entry.vuln_id,
                    object_id=assertion_id,
                    props={"source": "legacy-vulnerability-registry"},
                ),
                GraphEdge(
                    edge_id=_stable_id("EDGE-MAPS-TO", assertion_id, entry.cwe_id),
                    edge_type="MAPS_TO",
                    subject_id=assertion_id,
                    object_id=entry.cwe_id,
                    props={"source": "legacy-vulnerability-registry"},
                ),
            )
        )
        assertion_count += 1

    repository.atomic_write(nodes=nodes, edges=edges)
    return LegacyRegistryMigrationReport(
        target_schema="ckg-v2",
        vulnerability_count=len(registry.vulnerabilities),
        evidence_count=evidence_count,
        weakness_assertion_count=assertion_count,
        product_count=len(products),
        component_count=len(components),
        version_range_count=len(ranges),
        unresolved_cwe_ids=tuple(sorted(unresolved_cwes)),
        missing_snapshot_evidence_ids=tuple(sorted(missing_snapshots)),
        skipped_assertion_vulnerability_ids=tuple(sorted(skipped_assertions)),
        diagnostics=tuple(sorted(diagnostics)),
    )
