from dataclasses import dataclass

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.ingestion.cwe.parser import ParsedCWECatalog


def _edge_type(predicate: str) -> str:
    chunks: list[str] = []
    for character in predicate:
        if character.isupper() and chunks:
            chunks.append("_")
        chunks.append(character.upper())
    return "".join(chunks)


@dataclass(frozen=True)
class CWEImportReport:
    weakness_count: int
    relation_count: int
    unresolved_relation_ids: tuple[str, ...]
    group_count: int = 0
    membership_count: int = 0
    unresolved_group_memberships: tuple[tuple[str, str, str | None], ...] = ()


def import_cwe_catalog(repository: GraphRepository, catalog: ParsedCWECatalog) -> CWEImportReport:
    existing_ids = {node.node_id for node in repository.nodes("CWE")}
    imported_ids = {weakness.cwe_id for weakness in catalog.weaknesses}
    revision_id = f"CWE-REVISION-{catalog.source_release}-{catalog.weaknesses[0].source_snapshot_digest.removeprefix('sha256:')[:24]}" if catalog.weaknesses else f"CWE-REVISION-{catalog.source_release}"
    retrieved_at = catalog.weaknesses[0].retrieved_at if catalog.weaknesses else None
    nodes = [
        GraphNode(
            label="CanonicalCatalogRevision",
            node_id=revision_id,
            props={
                "catalog": "CWE",
                "source_release": catalog.source_release,
                "source_snapshot_digest": catalog.weaknesses[0].source_snapshot_digest if catalog.weaknesses else None,
                "retrieved_at": retrieved_at.isoformat() if retrieved_at else None,
                "status": "CANONICAL",
            },
        )
    ]
    existing_cwe = {node.node_id: node for node in repository.nodes("CWE")}
    cwe_nodes = []
    for weakness in catalog.weaknesses:
        props = weakness.model_dump(mode="json", exclude_none=True)
        if weakness.cwe_id in existing_cwe:
            old_props = existing_cwe[weakness.cwe_id].props
            old_time = old_props.get("first_seen_at") or old_props.get("retrieved_at")
            new_time = props.get("retrieved_at")
            if old_time and new_time:
                props["first_seen_at"] = min(str(old_time), str(new_time))
            elif old_time:
                props["first_seen_at"] = str(old_time)
            elif new_time:
                props["first_seen_at"] = str(new_time)
            props["retrieved_at"] = props.get("first_seen_at") or props.get("retrieved_at")
        else:
            if props.get("retrieved_at"):
                props["first_seen_at"] = props["retrieved_at"]
        cwe_nodes.append(GraphNode(label="CWE", node_id=weakness.cwe_id, props=props))
    nodes.extend(cwe_nodes)

    def _cwe_content_id(w) -> str:
        digest_part = f"-{w.source_snapshot_digest.removeprefix('sha256:')[:16]}" if w.source_snapshot_digest else ""
        return f"CWE-CONTENT-{w.cwe_id}-{catalog.source_release}{digest_part}"

    existing_content = {node.node_id for node in repository.nodes("CWEContentRevision")}
    # Content identity includes release and snapshot digest.  Replaying the
    # same bytes must not change when that fact first became available.
    nodes.extend(
        GraphNode(
            label="CWEContentRevision",
            node_id=_cwe_content_id(weakness),
            props={
                **weakness.model_dump(mode="json", exclude_none=True),
                "canonical_id": weakness.cwe_id,
                "source_release": catalog.source_release,
                "retrieved_at": weakness.retrieved_at.isoformat() if weakness.retrieved_at else (retrieved_at.isoformat() if retrieved_at else None),
            },
        )
        for weakness in catalog.weaknesses
        if _cwe_content_id(weakness) not in existing_content
    )
    nodes.extend(GraphNode(label="CWECategory" if group.kind == "CATEGORY" else "CWEView", node_id=group.group_id, props=group.model_dump(mode="json", exclude_none=True)) for group in catalog.groups)
    available_ids = existing_ids | imported_ids
    edges: list[GraphEdge] = []
    relation_count = 0
    membership_count = 0
    unresolved_memberships: list[tuple[str, str, str | None]] = []
    unresolved: list[str] = []
    for relation in catalog.relations:
        if relation.subject_cwe_id not in available_ids or relation.object_cwe_id not in available_ids:
            unresolved.append(relation.relation_id)
            continue
        edges.append(
            GraphEdge(
                edge_id=relation.relation_id,
                edge_type=_edge_type(relation.predicate),
                subject_id=relation.subject_cwe_id,
                object_id=relation.object_cwe_id,
                props={
                    "raw_predicate": relation.predicate,
                    "source_release": relation.source_release,
                    "source_snapshot_digest": relation.source_snapshot_digest,
                    "view_id": relation.view_id,
                    "qualifier": relation.qualifier,
                    "source_id": relation.provenance.source_id,
                    "retrieved_at": relation.provenance.retrieved_at.isoformat(),
                },
            )
        )
        relation_count += 1
    for group_id, cwe_id, view_id in catalog.group_memberships:
        if cwe_id not in available_ids:
            unresolved_memberships.append((group_id, cwe_id, view_id))
            continue
        edges.append(
            GraphEdge(
                edge_id=f"{group_id}-HAS-MEMBER-{cwe_id}-{view_id or 'NONE'}-{catalog.source_release}",
                edge_type="HAS_MEMBER",
                subject_id=group_id,
                object_id=cwe_id,
                props={
                    "view_id": view_id,
                    "source_release": catalog.source_release,
                    "retrieved_at": retrieved_at.isoformat() if retrieved_at else None,
                },
            )
        )
        membership_count += 1
    for cwe_id in sorted(imported_ids):
        edges.append(
            GraphEdge(
                edge_id=f"EDGE-CWE-REVISION-{revision_id}-{cwe_id}",
                edge_type="HAS_CANONICAL_REVISION",
                subject_id=revision_id,
                object_id=cwe_id,
                props={"retrieved_at": retrieved_at.isoformat() if retrieved_at else None},
            )
        )
    repository.atomic_write(nodes=nodes, edges=edges)
    return CWEImportReport(
        len(catalog.weaknesses),
        relation_count,
        tuple(sorted(unresolved)),
        len(catalog.groups),
        membership_count,
        tuple(sorted(unresolved_memberships)),
    )
