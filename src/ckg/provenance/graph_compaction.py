"""Deterministic, provenance-preserving compaction of version range values."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ckg.graph.models import GraphEdge, GraphNode


_SEMANTIC_FIELDS = ("ecosystem", "expression", "status")


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


def version_range_id(ecosystem: str, expression: str, status: str) -> str:
    """Identify a version value independently of its products and sources."""

    return _stable_id("VERSION-RANGE", ecosystem, expression, status)


def affects_version_edge_id(subject_id: str, version_id: str, source_record_id: str) -> str:
    return _stable_id("EDGE-AFFECTS-VERSION", subject_id, version_id, source_record_id)


@dataclass(frozen=True)
class VersionRangeCompactionReport:
    original_version_range_count: int
    compacted_version_range_count: int
    original_affects_version_count: int
    compacted_affects_version_count: int


def _semantic_key(node: GraphNode) -> tuple[str, str, str]:
    values = tuple(node.props.get(field) for field in _SEMANTIC_FIELDS)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"VersionRange {node.node_id} has an incomplete semantic key")
    return values  # type: ignore[return-value]


def _original_records(item: GraphNode | GraphEdge, field: str) -> list[dict[str, Any]]:
    stored = item.props.get(field)
    if stored is not None:
        if not isinstance(stored, list):
            raise ValueError(f"invalid {field} on {item.node_id if isinstance(item, GraphNode) else item.edge_id}")
        return stored
    if isinstance(item, GraphNode):
        return [{"node_id": item.node_id, "props": dict(item.props)}]
    return [{"edge_id": item.edge_id, "props": dict(item.props)}]


def _values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, (list, tuple)):
        return {item for item in value if isinstance(item, str) and item}
    return set()


def compact_version_ranges(
    nodes: Iterable[GraphNode], edges: Iterable[GraphEdge]
) -> tuple[list[GraphNode], list[GraphEdge], VersionRangeCompactionReport]:
    """Share equal version values while retaining every source observation.

    The returned graph is a candidate projection; callers decide whether and
    when to persist it. Original records carry properties that disagree across
    merged nodes or edges. Product associations are kept on version edges.
    """

    all_nodes = list(nodes)
    all_edges = list(edges)
    if len({node.node_id for node in all_nodes}) != len(all_nodes):
        raise ValueError("duplicate node identity in compaction input")
    edge_identity: dict[str, GraphEdge] = {}
    for edge in all_edges:
        prior = edge_identity.get(edge.edge_id)
        if prior is not None and not (
            edge.edge_type == prior.edge_type == "AFFECTS_VERSION"
            and edge.subject_id == prior.subject_id
            and edge.object_id == prior.object_id
            and isinstance(edge.props.get("source_record_id"), str)
            and bool(edge.props["source_record_id"])
            and edge.props["source_record_id"] == prior.props.get("source_record_id")
        ):
            raise ValueError(f"duplicate edge identity in compaction input: {edge.edge_id}")
        edge_identity[edge.edge_id] = edge

    by_id = {node.node_id: node for node in all_nodes}
    ranges: dict[tuple[str, str, str], list[GraphNode]] = defaultdict(list)
    remap: dict[str, str] = {}
    for node in all_nodes:
        if node.label == "VersionRange":
            key = _semantic_key(node)
            ranges[key].append(node)
            remap[node.node_id] = version_range_id(*key)

    # Old importer versions stored the affected product pointer on the range
    # node, but only its source record on AFFECTS_VERSION. Match that pointer
    # against AFFECTS or verify the former product-based range ID. The latter
    # also works when the node pointer was overwritten by a later source.
    products_by_pointer: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    products_by_subject: dict[str, set[str]] = defaultdict(set)
    for edge in all_edges:
        if edge.edge_type != "AFFECTS":
            continue
        products_by_subject[edge.subject_id].add(edge.object_id)
        source = edge.props.get("source_record_id")
        pointers = _values(edge.props.get("source_pointer")) | _values(edge.props.get("source_pointers"))
        if isinstance(source, str) and source:
            for pointer in pointers:
                products_by_pointer[(edge.subject_id, source, pointer)].add(edge.object_id)

    compacted_nodes = [node for node in all_nodes if node.label != "VersionRange"]
    for key, group in sorted(ranges.items()):
        canonical_id = version_range_id(*key)
        if len(group) == 1 and group[0].node_id == canonical_id:
            compacted_nodes.append(group[0])
            continue
        originals = sorted(
            (record for node in group for record in _original_records(node, "original_nodes")),
            key=lambda record: record["node_id"],
        )
        pointers = sorted({
            pointer
            for record in originals
            for pointer in _values(record["props"].get("source_pointer"))
            | _values(record["props"].get("source_pointers"))
        })
        compacted_nodes.append(GraphNode(
            label="VersionRange",
            node_id=canonical_id,
            props={
                **dict(zip(_SEMANTIC_FIELDS, key)),
                "original_node_ids": sorted({record["node_id"] for record in originals}),
                "original_nodes": originals,
                "source_pointers": pointers,
            },
        ))

    version_edges: dict[tuple[str, str, tuple[str, str]], list[GraphEdge]] = defaultdict(list)
    compacted_edges: list[GraphEdge] = []
    for edge in all_edges:
        if edge.edge_type == "AFFECTS_VERSION":
            target = remap.get(edge.object_id)
            if target is None:
                raise ValueError(f"AFFECTS_VERSION {edge.edge_id} has no VersionRange target")
            source = edge.props.get("source_record_id")
            # Without source identity, separate observations cannot safely be
            # aggregated, even when subject and version value agree.
            source_key = (source, "") if isinstance(source, str) and source else ("", edge.edge_id)
            version_edges[(edge.subject_id, target, source_key)].append(edge)
        else:
            compacted_edges.append(GraphEdge(
                edge_id=edge.edge_id,
                edge_type=edge.edge_type,
                subject_id=remap.get(edge.subject_id, edge.subject_id),
                object_id=remap.get(edge.object_id, edge.object_id),
                props=dict(edge.props),
            ))

    for (subject, target, _source_key), group in sorted(version_edges.items()):
        if len(group) == 1 and group[0].object_id == target and all(
            field in group[0].props for field in
            ("product_ids", "source_pointers", "product_associations", "original_edges")
        ):
            compacted_edges.append(group[0])
            continue
        unique_originals = {
            json.dumps(record, sort_keys=True): record
            for edge in group for record in _original_records(edge, "original_edges")
        }
        originals = sorted(
            unique_originals.values(),
            key=lambda record: (record["edge_id"], json.dumps(record["props"], sort_keys=True)),
        )
        product_ids: set[str] = set()
        pointers: set[str] = set()
        associations: list[dict[str, Any]] = []
        for edge in group:
            old_range = by_id[edge.object_id]
            direct_pointers = _values(edge.props.get("source_pointer")) | _values(edge.props.get("source_pointers"))
            node_pointers = _values(old_range.props.get("source_pointer")) | _values(old_range.props.get("source_pointers"))
            edge_pointers = direct_pointers | node_pointers
            pointers |= edge_pointers
            explicit_products = _values(edge.props.get("product_id")) | _values(edge.props.get("product_ids"))
            source = edge.props.get("source_record_id")
            pointer_matches: dict[str, set[str]] = {}
            hash_products: set[str] = set()
            for product_id in products_by_subject.get(subject, set()):
                if old_range.node_id == _stable_id(
                    "VERSION-RANGE", product_id,
                    str(old_range.props["expression"]), str(old_range.props["status"]),
                ):
                    hash_products.add(product_id)
            if isinstance(source, str) and source:
                for pointer in edge_pointers:
                    matches = products_by_pointer.get((subject, source, pointer), set())
                    if pointer in direct_pointers:
                        pointer_matches[pointer] = matches
                    elif hash_products:
                        pointer_matches[pointer] = matches & hash_products
            existing_associations = edge.props.get("product_associations")
            if isinstance(existing_associations, list):
                if not all(isinstance(item, dict) for item in existing_associations):
                    raise ValueError(f"invalid product_associations on {edge.edge_id}")
                associations.extend(existing_associations)
                product_ids.update(
                    item["product_id"] for item in existing_associations
                    if isinstance(item.get("product_id"), str) and item["product_id"]
                )
                pointers.update(
                    item["source_pointer"] for item in existing_associations
                    if isinstance(item.get("source_pointer"), str) and item["source_pointer"]
                )
            else:
                known_products = explicit_products | hash_products | set().union(*pointer_matches.values())
                pairs: set[tuple[str | None, str | None]] = set()
                explicit_pointer = next(iter(direct_pointers)) if len(direct_pointers) == 1 else None
                pairs.update((product_id, explicit_pointer) for product_id in explicit_products)
                pairs.update(
                    (product_id, pointer)
                    for pointer, matches in pointer_matches.items()
                    for product_id in matches
                )
                already_linked = {product_id for product_id, _ in pairs}
                pairs.update((product_id, None) for product_id in hash_products - already_linked)
                if not pairs:
                    pairs.update((None, pointer) for pointer in edge_pointers or {None})
                associations.extend({
                    "product_id": product_id,
                    "source_pointer": pointer,
                    "original_node_id": edge.object_id,
                    "original_edge_id": edge.edge_id,
                } for product_id, pointer in sorted(pairs, key=lambda pair: (str(pair[0]), str(pair[1]))))
            product_ids.update(explicit_products | hash_products | set().union(*pointer_matches.values()))
        source_id = group[0].props.get("source_record_id")
        edge_id = (
            affects_version_edge_id(subject, target, source_id)
            if isinstance(source_id, str) and source_id
            else group[0].edge_id
        )
        compacted_edges.append(GraphEdge(
            edge_id=edge_id,
            edge_type="AFFECTS_VERSION",
            subject_id=subject,
            object_id=target,
            props={
                **({"source_record_id": source_id} if isinstance(source_id, str) and source_id else {}),
                "product_ids": sorted(product_ids),
                "source_pointers": sorted(pointers),
                "product_associations": sorted(
                    {json.dumps(item, sort_keys=True): item for item in associations}.values(),
                    key=lambda item: (str(item.get("product_id")), str(item.get("source_pointer")), str(item.get("original_edge_id"))),
                ),
                "original_edge_ids": sorted({record["edge_id"] for record in originals}),
                "original_edges": originals,
            },
        ))

    compacted_nodes.sort(key=lambda node: node.node_id)
    compacted_edges.sort(key=lambda edge: edge.edge_id)
    if len({node.node_id for node in compacted_nodes}) != len(compacted_nodes):
        raise ValueError("node identity collision after version range compaction")
    if len({edge.edge_id for edge in compacted_edges}) != len(compacted_edges):
        raise ValueError("edge identity collision after version range compaction")
    report = VersionRangeCompactionReport(
        original_version_range_count=sum(map(len, ranges.values())),
        compacted_version_range_count=len(ranges),
        original_affects_version_count=sum(map(len, version_edges.values())),
        compacted_affects_version_count=len(version_edges),
    )
    return compacted_nodes, compacted_edges, report
