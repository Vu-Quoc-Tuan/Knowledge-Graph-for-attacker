from __future__ import annotations

from pydantic import Field

from ckg.domain.value_objects.base import DomainModel
from ckg.domain.value_objects.evidence_span import EvidenceSpan


class FacetCandidate(DomainModel):
    """A candidate is not a graph assertion until a resolver accepts it."""

    kind: str = Field(min_length=1)
    value: str = Field(min_length=1)
    normalized_id: str | None = None
    extractor_name: str = Field(min_length=1)
    extractor_version: str = Field(min_length=1)
    evidence_spans: tuple[EvidenceSpan, ...] = Field(min_length=1)
    modality_scores: dict[str, float] = Field(default_factory=dict)


class ExtractionResult(DomainModel):
    candidates: tuple[FacetCandidate, ...] = ()
    abstentions: tuple[str, ...] = ()
