"""Materialize patch patterns as evidence-grounded context, never raw diffs."""

from __future__ import annotations

import hashlib
from datetime import datetime

from ckg.domain.enums.fact_status import FactStatus
from ckg.extraction.models import FacetCandidate
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.linking.cwe.scorer import score_modalities


def materialize_patch_pattern(
    repository: GraphRepository,
    *,
    vulnerability_id: str,
    candidate: FacetCandidate,
    retrieved_at: datetime,
) -> str | None:
    if candidate.kind != "PatchPattern" or not candidate.normalized_id:
        return None
    score = score_modalities(candidate.modality_scores)
    if score.relevance is None or score.evidence_coverage < 0.10:
        return None
    pattern_id = candidate.normalized_id
    node_exists = pattern_id in {node.node_id for node in repository.nodes("PatchPattern")}
    span = candidate.evidence_spans[0]
    edge_id = "EDGE-HAS-PATCH-PATTERN-" + hashlib.sha256(
        "\x1f".join((vulnerability_id, pattern_id, span.evidence_id, span.locator)).encode()
    ).hexdigest()[:24]
    repository.atomic_write(
        nodes=[] if node_exists else [GraphNode(
            label="PatchPattern",
            node_id=pattern_id,
            props={
                "pattern_id": pattern_id,
                "name": candidate.value,
                "status": FactStatus.EXTRACTED.value,
                "retrieved_at": retrieved_at.isoformat(),
            },
        )],
        edges=[GraphEdge(
            edge_id=edge_id,
            edge_type="HAS_PATCH_PATTERN",
            subject_id=vulnerability_id,
            object_id=pattern_id,
            props={
                "evidence_spans": [span.model_dump(mode="json") for span in candidate.evidence_spans],
                "relevance": score.relevance,
                "evidence_coverage": score.evidence_coverage,
                "retrieved_at": retrieved_at.isoformat(),
            },
        )],
    )
    return pattern_id
