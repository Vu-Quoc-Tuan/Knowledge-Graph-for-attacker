from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from ckg.domain.entities.assertion import TechniqueAssertion
from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.enums.relation_origin import RelationOrigin
from ckg.domain.value_objects.confidence import Confidence
from ckg.domain.value_objects.provenance import Provenance
from ckg.extraction.models import FacetCandidate
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.linking.cwe.scorer import LinkScore, score_modalities


@dataclass(frozen=True)
class TechniqueResolution:
    assertion_id: str | None
    technique_id: str | None
    score: LinkScore
    abstention: str | None


def resolve_technique(repository: GraphRepository, *, vulnerability_id: str, candidate: FacetCandidate, technique_id: str, relation: str, retrieved_at: datetime, min_relevance: float = 0.70, min_coverage: float = 0.10) -> TechniqueResolution:
    score = score_modalities(candidate.modality_scores)
    if candidate.kind != "Technique":
        return TechniqueResolution(None, None, score, "candidate is not a technique")
    if technique_id not in {node.node_id for node in repository.nodes("Technique")}:
        return TechniqueResolution(None, None, score, f"unknown technique {technique_id}")
    if score.relevance is None or score.relevance < min_relevance or score.evidence_coverage < min_coverage:
        return TechniqueResolution(None, None, score, "insufficient relevance or evidence coverage")
    span = candidate.evidence_spans[0]
    assertion_id = "TAS-EXTRACTED-" + hashlib.sha256(chr(31).join((vulnerability_id, technique_id, span.evidence_id, span.locator)).encode()).hexdigest()[:24]
    confidence = Confidence(relevance=score.relevance, evidence_coverage=score.evidence_coverage, final=min(score.relevance, score.evidence_coverage))
    assertion = TechniqueAssertion(assertion_id=assertion_id, vulnerability_id=vulnerability_id, technique_id=technique_id, relation=relation, status=FactStatus.EXTRACTED, provenance=Provenance(source_id=span.evidence_id, source_kind="facet_extraction", retrieved_at=retrieved_at, origin=RelationOrigin.EXTRACTION, extractor_name=candidate.extractor_name, extractor_version=candidate.extractor_version), evidence_spans=candidate.evidence_spans, confidence=confidence)
    repository.atomic_write(nodes=[GraphNode(label="TechniqueAssertion", node_id=assertion_id, props=assertion.model_dump(mode="json", exclude_none=True))], edges=[GraphEdge(edge_id=f"EDGE-HAS-TAS-{assertion_id}", edge_type="HAS_TECHNIQUE_ASSERTION", subject_id=vulnerability_id, object_id=assertion_id), GraphEdge(edge_id=f"EDGE-TAS-MAPS-TO-{assertion_id}-{technique_id}", edge_type="MAPS_TO", subject_id=assertion_id, object_id=technique_id)])
    return TechniqueResolution(assertion_id, technique_id, score, None)
