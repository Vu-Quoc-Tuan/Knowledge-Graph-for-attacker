from __future__ import annotations

import hashlib
from datetime import datetime

from ckg.domain.enums.fact_status import FactStatus
from ckg.extraction.models import FacetCandidate
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.linking.cwe.scorer import score_modalities


def materialize_context_assertion(repository: GraphRepository, *, vulnerability_id: str, candidate: FacetCandidate, context_label: str, retrieved_at: datetime) -> str | None:
    """Store an extracted context association separately from canonical context nodes."""
    score = score_modalities(candidate.modality_scores)
    if score.relevance is None or score.evidence_coverage < 0.10 or candidate.normalized_id is None:
        return None
    assertion_id = "CTX-ASSERT-" + hashlib.sha256(chr(31).join((vulnerability_id, candidate.normalized_id, candidate.evidence_spans[0].locator)).encode()).hexdigest()[:24]
    if candidate.normalized_id not in {node.node_id for node in repository.nodes(context_label)}:
        return None
    repository.atomic_write(nodes=[GraphNode(label="ContextAssertion", node_id=assertion_id, props={"assertion_id": assertion_id, "vulnerability_id": vulnerability_id, "context_id": candidate.normalized_id, "kind": candidate.kind, "status": FactStatus.EXTRACTED.value, "relevance": score.relevance, "evidence_coverage": score.evidence_coverage, "evidence_spans": [span.model_dump(mode="json") for span in candidate.evidence_spans], "retrieved_at": retrieved_at.isoformat()})], edges=[GraphEdge(edge_id=f"EDGE-HAS-CONTEXT-{assertion_id}", edge_type="HAS_CONTEXT_ASSERTION", subject_id=vulnerability_id, object_id=assertion_id), GraphEdge(edge_id=f"EDGE-CONTEXT-MAPS-{assertion_id}-{candidate.normalized_id}", edge_type="MAPS_TO", subject_id=assertion_id, object_id=candidate.normalized_id)])
    return assertion_id
