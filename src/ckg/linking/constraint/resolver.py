"""Map extracted constraint phrases to explicit three-valued expressions."""

from __future__ import annotations

from datetime import datetime

from ckg.domain.entities.constraint import ApplicabilityConstraint
from ckg.extraction.models import FacetCandidate
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.linking.cwe.scorer import score_modalities


_EXPRESSIONS = {
    "CONSTRAINT-EXTERNAL-ENTITIES-ENABLED": {"kind": "configuration", "key": "external_entities", "equals": True},
    "CONSTRAINT-EXTERNAL-ENTITIES-DISABLED": {"kind": "configuration", "key": "external_entities", "equals": False},
    "CONSTRAINT-NETWORK-EGRESS-ALLOWED": {"kind": "network", "key": "dns_egress", "equals": True},
}


def materialize_constraint(repository: GraphRepository, *, vulnerability_id: str, candidate: FacetCandidate, retrieved_at: datetime) -> str | None:
    if candidate.kind != "Constraint" or candidate.normalized_id not in _EXPRESSIONS:
        return None
    score = score_modalities(candidate.modality_scores)
    if score.relevance is None or score.evidence_coverage < 0.10:
        return None
    constraint_id = candidate.normalized_id
    constraint = ApplicabilityConstraint(constraint_id=constraint_id, kind="expression", expression=__import__("json").dumps(_EXPRESSIONS[constraint_id], sort_keys=True))
    node_exists = constraint_id in {node.node_id for node in repository.nodes("ApplicabilityConstraint")}
    nodes = [] if node_exists else [GraphNode(label="ApplicabilityConstraint", node_id=constraint_id, props={**constraint.model_dump(mode="json"), "source_status": "EXTRACTED", "retrieved_at": retrieved_at.isoformat()})]
    edge_id = f"EDGE-REQUIRES-CONSTRAINT-{vulnerability_id}-{constraint_id}-{candidate.evidence_spans[0].locator.rsplit('/', 1)[-1]}"
    repository.atomic_write(nodes=nodes, edges=[GraphEdge(edge_id=edge_id, edge_type="REQUIRES_CONSTRAINT", subject_id=vulnerability_id, object_id=constraint_id, props={"evidence_spans": [span.model_dump(mode="json") for span in candidate.evidence_spans], "relevance": score.relevance, "evidence_coverage": score.evidence_coverage})])
    return constraint_id
