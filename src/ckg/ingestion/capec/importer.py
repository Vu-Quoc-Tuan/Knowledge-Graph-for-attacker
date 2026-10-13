from dataclasses import dataclass

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.ingestion.capec.parser import ParsedCAPECCatalog


@dataclass(frozen=True)
class CAPECImportReport:
    pattern_count: int
    related_weakness_count: int
    unresolved_cwe_ids: tuple[str, ...]
    step_count: int = 0
    prerequisite_count: int = 0


def import_capec_catalog(repository: GraphRepository, catalog: ParsedCAPECCatalog) -> CAPECImportReport:
    cwe_ids = {node.node_id for node in repository.nodes("CWE")}
    revision_id = f"CAPEC-REVISION-{catalog.source_release}-{catalog.patterns[0].source_snapshot_digest.removeprefix('sha256:')[:24]}" if catalog.patterns else f"CAPEC-REVISION-{catalog.source_release}"
    retrieved_at = catalog.patterns[0].retrieved_at if catalog.patterns else None
    nodes = [
        GraphNode(
            label="CanonicalCatalogRevision",
            node_id=revision_id,
            props={
                "catalog": "CAPEC",
                "source_release": catalog.source_release,
                "source_snapshot_digest": catalog.patterns[0].source_snapshot_digest if catalog.patterns else None,
                "retrieved_at": retrieved_at.isoformat() if retrieved_at else None,
                "status": "CANONICAL",
            },
        )
    ]
    existing_capec = {node.node_id: node for node in repository.nodes("CAPEC")}
    capec_nodes = []
    for pattern in catalog.patterns:
        props = pattern.model_dump(mode="json", exclude_none=True)
        if pattern.capec_id in existing_capec:
            old_props = existing_capec[pattern.capec_id].props
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
        capec_nodes.append(GraphNode(label="CAPEC", node_id=pattern.capec_id, props=props))
    nodes.extend(capec_nodes)

    def _capec_content_id(p) -> str:
        digest_part = f"-{p.source_snapshot_digest.removeprefix('sha256:')[:16]}" if p.source_snapshot_digest else ""
        return f"CAPEC-CONTENT-{p.capec_id}-{catalog.source_release}{digest_part}"

    existing_content = {node.node_id for node in repository.nodes("CAPECContentRevision")}
    nodes.extend(
        GraphNode(
            label="CAPECContentRevision",
            node_id=_capec_content_id(pattern),
            props={
                **pattern.model_dump(mode="json", exclude_none=True),
                "canonical_id": pattern.capec_id,
                "source_release": catalog.source_release,
                "retrieved_at": pattern.retrieved_at.isoformat() if pattern.retrieved_at else (retrieved_at.isoformat() if retrieved_at else None),
            },
        )
        for pattern in catalog.patterns
        if _capec_content_id(pattern) not in existing_content
    )
    nodes.extend(GraphNode(label="AttackStep", node_id=step.step_id, props=step.model_dump(mode="json", exclude_none=True)) for step in catalog.steps)
    nodes.extend(GraphNode(label="AttackPrerequisite", node_id=item.prerequisite_id, props=item.model_dump(mode="json", exclude_none=True)) for item in catalog.prerequisites)
    edges: list[GraphEdge] = []
    unresolved: set[str] = set()
    related_weakness_count = 0
    for relation in catalog.related_weaknesses:
        if relation.cwe_id not in cwe_ids:
            unresolved.add(relation.cwe_id)
            continue
        edges.append(
            GraphEdge(
                edge_id=relation.relation_id,
                edge_type="RELATED_WEAKNESS",
                subject_id=relation.capec_id,
                object_id=relation.cwe_id,
                props={
                    "source_id": relation.provenance.source_id,
                    "source_release": relation.provenance.source_release,
                    "retrieved_at": relation.provenance.retrieved_at.isoformat(),
                },
            )
        )
        related_weakness_count += 1
    for step in catalog.steps:
        edges.append(GraphEdge(edge_id=f"{step.capec_id}-HAS-STEP-{step.ordinal}", edge_type="HAS_ATTACK_STEP", subject_id=step.capec_id, object_id=step.step_id, props={"ordinal": step.ordinal, "retrieved_at": retrieved_at.isoformat() if retrieved_at else None}))
    for item in catalog.prerequisites:
        edges.append(GraphEdge(edge_id=f"{item.capec_id}-HAS-PREREQUISITE-{item.ordinal}", edge_type="HAS_PREREQUISITE", subject_id=item.capec_id, object_id=item.prerequisite_id, props={"ordinal": item.ordinal, "retrieved_at": retrieved_at.isoformat() if retrieved_at else None}))
    for pattern in catalog.patterns:
        edges.append(GraphEdge(edge_id=f"EDGE-CAPEC-REVISION-{revision_id}-{pattern.capec_id}", edge_type="HAS_CANONICAL_REVISION", subject_id=revision_id, object_id=pattern.capec_id, props={"retrieved_at": retrieved_at.isoformat() if retrieved_at else None}))
    repository.atomic_write(nodes=nodes, edges=edges)
    return CAPECImportReport(len(catalog.patterns), related_weakness_count, tuple(sorted(unresolved)), len(catalog.steps), len(catalog.prerequisites))
