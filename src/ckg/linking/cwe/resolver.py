from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from ckg.domain.entities.assertion import WeaknessAssertion
from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.enums.relation_origin import RelationOrigin
from ckg.domain.value_objects.confidence import Confidence
from ckg.domain.value_objects.provenance import Provenance
from ckg.extraction.models import FacetCandidate
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.linking.cwe.scorer import LinkScore, score_modalities


def _identifier(*parts: str) -> str:
    return "WAS-EXTRACTED-" + hashlib.sha256(chr(31).join(parts).encode()).hexdigest()[:24]


@dataclass(frozen=True)
class Resolution:
    assertion_id: str | None
    cwe_id: str | None
    score: LinkScore
    abstention: str | None


def resolve_weakness(
    repository: GraphRepository,
    *,
    vulnerability_id: str,
    candidate: FacetCandidate,
    cwe_id: str,
    retrieved_at: datetime,
    min_relevance: float = 0.70,
    min_coverage: float = 0.10,
) -> Resolution:
    score = score_modalities(candidate.modality_scores)
    if candidate.kind != "Weakness":
        return Resolution(None, None, score, "candidate is not a weakness")
    if cwe_id not in {node.node_id for node in repository.nodes("CWE")}:
        return Resolution(None, None, score, f"unknown canonical CWE {cwe_id}")
    if not candidate.evidence_spans:
        return Resolution(None, None, score, "missing evidence span")
    if score.relevance is None or score.relevance < min_relevance or score.evidence_coverage < min_coverage:
        return Resolution(None, None, score, "insufficient relevance or evidence coverage")
    assertion_id = _identifier(vulnerability_id, cwe_id, candidate.evidence_spans[0].evidence_id, candidate.evidence_spans[0].locator)
    confidence = Confidence(relevance=score.relevance, evidence_coverage=score.evidence_coverage, final=min(score.relevance, score.evidence_coverage))
    assertion = WeaknessAssertion(assertion_id=assertion_id, vulnerability_id=vulnerability_id, cwe_id=cwe_id, status=FactStatus.EXTRACTED, provenance=Provenance(source_id=candidate.evidence_spans[0].evidence_id, source_kind="facet_extraction", retrieved_at=retrieved_at, origin=RelationOrigin.EXTRACTION, extractor_name=candidate.extractor_name, extractor_version=candidate.extractor_version), evidence_spans=candidate.evidence_spans, confidence=confidence, relevance=score.relevance, role="extracted")
    repository.atomic_write(nodes=[GraphNode(label="WeaknessAssertion", node_id=assertion_id, props=assertion.model_dump(mode="json", exclude_none=True))], edges=[GraphEdge(edge_id=f"EDGE-HAS-WAS-{assertion_id}", edge_type="HAS_WEAKNESS_ASSERTION", subject_id=vulnerability_id, object_id=assertion_id), GraphEdge(edge_id=f"EDGE-MAPS-TO-{assertion_id}-{cwe_id}", edge_type="MAPS_TO", subject_id=assertion_id, object_id=cwe_id)])
    return Resolution(assertion_id, cwe_id, score, None)
