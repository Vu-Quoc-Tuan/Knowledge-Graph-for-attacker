"""Build a bounded, provenance-preserving CKG projection for a CWE focus set.

The focused graph is a materialized experiment projection.  It is built from
the current v2 graph in memory, so the active Neo4j projection is not touched
until the complete candidate graph passes validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from ckg.graph.models import GraphEdge, GraphNode
from ckg.provenance.compact_details import is_compact_detail_node


FOCUSED_CWE_IDS: frozenset[str] = frozenset(
    {
        "CWE-89",
        "CWE-564",
        "CWE-74",
        "CWE-78",
        "CWE-79",
        "CWE-88",
        "CWE-434",
        "CWE-22",
        "CWE-94",
        "CWE-918",
    }
)

PATT_NATIVE_CWE_IDS: frozenset[str] = frozenset(
    {"CWE-89", "CWE-78", "CWE-79", "CWE-434", "CWE-22", "CWE-94", "CWE-918"}
)

_DERIVED_LABELS = frozenset({"Scenario", "CWEContextProfile", "Cooccurrence"})
_PATT_GRANULAR_LABELS = frozenset({"Payload", "PATTSection"})
_VULNERABILITY_LABELS = frozenset({"CVE", "GHSA"})
_WSTG_REFERENCE_LABELS = frozenset(
    {
        "WSTGCase",
        "TestStrategy",
        "Evidence",
        "Technique",
        "CallbackChannel",
        "Oracle",
        "InputSurface",
        "ApplicabilityConstraint",
    }
)
_WSTG_SOURCE_EDGE_TYPES = frozenset(
    {
        "DESCRIBES",
        "SUPPORTED_BY",
        "USES_TECHNIQUE",
        "USES_CHANNEL",
        "USES_ORACLE",
        "APPLIES_TO",
    }
)


@dataclass(frozen=True)
class FocusedProjectionReport:
    target_cwes: tuple[str, ...]
    cwe_count: int
    cve_count: int
    excluded_cves: tuple[str, ...]
    capec_count: int
    wstg_case_count: int
    strategy_count: int
    patt_document_count: int
    patt_payload_count: int
    node_count: int
    edge_count: int


def _index(nodes: Iterable[GraphNode]) -> dict[str, GraphNode]:
    return {node.node_id: node for node in nodes}


def _add(keep: set[str], node_ids: Iterable[str], labels: dict[str, str], allowed: set[str] | None = None) -> None:
    for node_id in node_ids:
        if node_id not in labels:
            continue
        if allowed is not None and labels[node_id] not in allowed:
            continue
        keep.add(node_id)


def _closure(
    keep: set[str],
    edges: list[GraphEdge],
    labels: dict[str, str],
    *,
    edge_types: frozenset[str],
    allowed_labels: frozenset[str],
) -> None:
    """Add one bounded source-plane closure around already selected nodes."""
    changed = True
    while changed:
        changed = False
        for edge in edges:
            if edge.edge_type not in edge_types:
                continue
            if edge.subject_id in keep and edge.object_id not in keep:
                if labels.get(edge.object_id) in allowed_labels:
                    keep.add(edge.object_id)
                    changed = True
            elif edge.object_id in keep and edge.subject_id not in keep:
                if labels.get(edge.subject_id) in allowed_labels:
                    keep.add(edge.subject_id)
                    changed = True


def build_focused_projection(
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
    *,
    target_cwes: frozenset[str] = FOCUSED_CWE_IDS,
) -> tuple[list[GraphNode], list[GraphEdge], FocusedProjectionReport]:
    """Select canonical, source-backed data relevant to ``target_cwes``.

    Existing derived scenarios and learned profiles are intentionally omitted;
    they must be regenerated on the focused projection rather than copied from
    the full graph.
    """
    all_nodes = list(nodes)
    all_edges = list(edges)
    by_id = _index(all_nodes)
    labels = {node.node_id: node.label for node in all_nodes}
    target_cwes = frozenset(target_cwes)
    missing = sorted(target_cwes - {node.node_id for node in all_nodes if node.label == "CWE"})
    if missing:
        raise ValueError(f"focused CWE set is missing from source graph: {', '.join(missing)}")

    keep: set[str] = set(target_cwes)
    keep.update(
        node.node_id
        for node in all_nodes
        if node.label == "CWEContentRevision" and node.props.get("canonical_id") in target_cwes
    )

    # Keep only views/categories that explicitly contain one of the selected
    # weaknesses.  This preserves useful taxonomy context without importing
    # every unrelated CWE node.
    for edge in all_edges:
        if edge.edge_type == "HAS_MEMBER" and edge.object_id in target_cwes:
            _add(keep, (edge.subject_id,), labels, {"CWECategory", "CWEView"})

    # CAPEC is retained by an exact canonical RELATED_WEAKNESS edge.
    capec_ids = {
        edge.subject_id
        for edge in all_edges
        if edge.edge_type == "RELATED_WEAKNESS"
        and edge.object_id in target_cwes
        and labels.get(edge.subject_id) == "CAPEC"
    }
    keep.update(capec_ids)
    keep.update(
        node.node_id
        for node in all_nodes
        if node.label == "CAPECContentRevision" and node.props.get("canonical_id") in capec_ids
    )
    _closure(
        keep,
        all_edges,
        labels,
        edge_types=frozenset({"HAS_ATTACK_STEP", "HAS_PREREQUISITE"}),
        allowed_labels=frozenset({"AttackStep", "AttackPrerequisite"}),
    )

    # WSTG is selected by explicit target mapping.  The old generic closure
    # was unsafe here: two strategies sharing a technique/channel/oracle could
    # pull each other into the projection, even when the second strategy had
    # no TARGETS_WEAKNESS edge to a focused CWE.  Keep only the directly mapped
    # strategies, their describing WSTG cases, and one-hop source references.
    strategy_ids = {
        edge.subject_id
        for edge in all_edges
        if edge.edge_type == "TARGETS_WEAKNESS"
        and edge.object_id in target_cwes
        and labels.get(edge.subject_id) == "TestStrategy"
    }
    keep.update(strategy_ids)
    wstg_case_ids = {
        edge.subject_id
        for edge in all_edges
        if edge.edge_type == "DESCRIBES"
        and edge.object_id in strategy_ids
        and labels.get(edge.subject_id) == "WSTGCase"
    }
    keep.update(wstg_case_ids)
    wstg_anchors = strategy_ids | wstg_case_ids
    reference_labels = _WSTG_REFERENCE_LABELS - frozenset({"WSTGCase", "TestStrategy"})
    for edge in all_edges:
        if edge.edge_type not in _WSTG_SOURCE_EDGE_TYPES:
            continue
        if edge.subject_id in wstg_anchors and labels.get(edge.object_id) in reference_labels:
            keep.add(edge.object_id)
        elif edge.object_id in wstg_anchors and labels.get(edge.subject_id) in reference_labels:
            keep.add(edge.subject_id)

    # Retain CVEs only when a reified weakness assertion maps to a selected CWE.
    mapped_assertions = {
        edge.subject_id
        for edge in all_edges
        if edge.edge_type == "MAPS_TO"
        and edge.object_id in target_cwes
        and labels.get(edge.subject_id) == "WeaknessAssertion"
    }
    cve_ids = {
        edge.subject_id
        for edge in all_edges
        if edge.edge_type == "HAS_WEAKNESS_ASSERTION"
        and edge.object_id in mapped_assertions
        and labels.get(edge.subject_id) in _VULNERABILITY_LABELS
    }
    keep.update(cve_ids)
    keep.update(mapped_assertions)

    # Keep vulnerability provenance and affected-product context, but never
    # copy old scenario/feedback/derived nodes into the experiment graph.
    for edge in all_edges:
        if edge.edge_type == "DESCRIBES" and edge.object_id in cve_ids and labels.get(edge.subject_id) == "VulnerabilitySourceRecord":
            keep.add(edge.subject_id)
        if edge.edge_type in {"SUPPORTED_BY", "AFFECTS", "AFFECTS_COMPONENT", "AFFECTS_VERSION"} and edge.subject_id in cve_ids:
            if labels.get(edge.object_id) in {"Product", "Component", "VersionRange"}:
                keep.add(edge.object_id)
            elif labels.get(edge.object_id) == "Evidence":
                # Legacy registry entries can intentionally carry only an
                # excerpt/hash marker when the source snapshot was never
                # captured.  Do not promote such unverifiable evidence into
                # the focused experiment graph.
                if by_id[edge.object_id].props.get("source_snapshot_available") is not False:
                    keep.add(edge.object_id)
    _closure(
        keep,
        all_edges,
        labels,
        edge_types=frozenset({"PART_OF"}),
        allowed_labels=frozenset({"Product", "Component"}),
    )
    for edge in all_edges:
        if edge.edge_type == "SUPPORTED_BY" and edge.subject_id in keep and labels.get(edge.object_id) == "Evidence":
            if by_id[edge.object_id].props.get("source_snapshot_available") is not False:
                keep.add(edge.object_id)

    # Keep catalog revision anchors only when their canonical endpoint remains
    # in the focused projection.
    for edge in all_edges:
        if edge.edge_type != "HAS_CANONICAL_REVISION" or edge.object_id not in keep:
            continue
        if labels.get(edge.subject_id) == "CanonicalCatalogRevision":
            keep.add(edge.subject_id)

    # Never allow derived or unrelated CWE nodes to leak through the closure.
    keep = {
        node_id
        for node_id in keep
        if labels.get(node_id) not in _DERIVED_LABELS
        and labels.get(node_id) not in _PATT_GRANULAR_LABELS
        and not is_compact_detail_node(by_id[node_id])
        and not (labels.get(node_id) == "CWE" and node_id not in target_cwes)
    }

    selected_nodes = [by_id[node_id] for node_id in sorted(keep)]
    selected_edges = [
        edge
        for edge in all_edges
        if edge.subject_id in keep and edge.object_id in keep
    ]
    selected_edges.sort(key=lambda edge: edge.edge_id)

    selected_cves = sorted(
        node_id for node_id in keep if labels.get(node_id) in _VULNERABILITY_LABELS
    )
    all_cves = {
        node.node_id for node in all_nodes if node.label in _VULNERABILITY_LABELS
    }
    excluded_cves = tuple(sorted(all_cves - set(selected_cves)))
    report = FocusedProjectionReport(
        target_cwes=tuple(sorted(target_cwes)),
        cwe_count=sum(node.label == "CWE" for node in selected_nodes),
        cve_count=len(selected_cves),
        excluded_cves=excluded_cves,
        capec_count=sum(node.label == "CAPEC" for node in selected_nodes),
        wstg_case_count=sum(node.label == "WSTGCase" for node in selected_nodes),
        strategy_count=sum(node.label == "TestStrategy" for node in selected_nodes),
        patt_document_count=sum(node.label == "PATTDocument" for node in selected_nodes),
        patt_payload_count=sum(node.label == "Payload" for node in selected_nodes),
        node_count=len(selected_nodes),
        edge_count=len(selected_edges),
    )
    return selected_nodes, selected_edges, report


def validate_focused_projection(
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
    *,
    target_cwes: frozenset[str] = FOCUSED_CWE_IDS,
) -> None:
    """Fail closed before a focused projection can replace Neo4j data."""
    selected_nodes = list(nodes)
    selected_edges = list(edges)
    by_id = _index(selected_nodes)
    granular_patt = [
        node.node_id
        for node in selected_nodes
        if node.label in _PATT_GRANULAR_LABELS or is_compact_detail_node(node)
    ]
    if granular_patt:
        raise ValueError(
            "focused projection contains non-canonical granular PATT/compact detail nodes: "
            + ", ".join(sorted(granular_patt)[:5])
        )
    if len(by_id) != len(selected_nodes):
        raise ValueError("focused projection contains duplicate node identities")
    for edge in selected_edges:
        if edge.subject_id not in by_id or edge.object_id not in by_id:
            raise ValueError(f"focused projection has dangling edge: {edge.edge_id}")
        endpoint_labels = {by_id[edge.subject_id].label, by_id[edge.object_id].label}
        if endpoint_labels & {"CVE", "GHSA"} and "CWE" in endpoint_labels:
            raise ValueError(f"focused projection contains direct vulnerability-to-CWE edge: {edge.edge_id}")
    actual_cwes = {node.node_id for node in selected_nodes if node.label == "CWE"}
    if actual_cwes != set(target_cwes):
        raise ValueError(
            "focused projection CWE mismatch: "
            f"expected {sorted(target_cwes)}, got {sorted(actual_cwes)}"
        )
    scenarios = [node.node_id for node in selected_nodes if node.label == "Scenario"]
    if scenarios:
        raise ValueError("focused projection contains stale scenarios: " + ", ".join(sorted(scenarios)[:5]))
    for node in selected_nodes:
        if node.label == "CWEContextProfile" and node.props.get("cwe_id") not in target_cwes:
            raise ValueError(f"focused profile points to out-of-scope CWE: {node.node_id}")
        if node.label == "Cooccurrence":
            pair = {node.props.get("left"), node.props.get("right")}
            if not pair <= set(target_cwes):
                raise ValueError(f"focused co-occurrence points out of scope: {node.node_id}")
    technology_names: dict[str, str] = {}
    for node in selected_nodes:
        if node.label != "Technology":
            continue
        name = str(node.props.get("name", "")).strip().casefold()
        if not name:
            raise ValueError(f"focused Technology node has no name: {node.node_id}")
        previous = technology_names.get(name)
        if previous is not None and previous != node.node_id:
            raise ValueError(f"focused projection has duplicate Technology name: {node.props.get('name')}")
        technology_names[name] = node.node_id
    for edge in selected_edges:
        if edge.edge_type == "MAPS_TO" and by_id[edge.object_id].label == "CWE" and edge.object_id not in target_cwes:
            raise ValueError(f"focused projection maps to out-of-scope CWE: {edge.edge_id}")
    mapped_strategy_ids = {
        edge.subject_id
        for edge in selected_edges
        if edge.edge_type == "TARGETS_WEAKNESS"
        and by_id[edge.subject_id].label == "TestStrategy"
        and by_id[edge.object_id].label == "CWE"
        and edge.object_id in target_cwes
    }
    orphan_strategies = {
        node.node_id
        for node in selected_nodes
        if node.label == "TestStrategy" and node.node_id not in mapped_strategy_ids
    }
    if orphan_strategies:
        raise ValueError(
            "focused projection contains WSTG strategies without a focused "
            f"TARGETS_WEAKNESS mapping: {', '.join(sorted(orphan_strategies)[:5])}"
        )
    unverifiable_evidence = {
        node.node_id
        for node in selected_nodes
        if node.label == "Evidence" and node.props.get("source_snapshot_available") is False
    }
    if unverifiable_evidence:
        raise ValueError(
            "focused projection contains evidence without a source snapshot: "
            f"{', '.join(sorted(unverifiable_evidence)[:5])}"
        )


def current_utc() -> datetime:
    return datetime.now(timezone.utc)
