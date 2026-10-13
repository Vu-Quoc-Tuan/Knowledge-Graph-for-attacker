from typing import Literal

from pydantic import Field

from ckg.domain.value_objects.base import DomainModel
from ckg.domain.value_objects.evidence_span import EvidenceSpan


class WeaknessOccurrence(DomainModel):
    occurrence_id: str = Field(min_length=1)
    vulnerability_id: str = Field(pattern=r"^(CVE-[0-9]{4}-[0-9]+|GHSA-[A-Za-z0-9-]+)$")
    cwe_id: str = Field(pattern=r"^CWE-[0-9]+$")
    scope_kind: Literal["component", "function", "data_flow", "request", "unknown"]
    scope_ref: str | None = None
    evidence_spans: tuple[EvidenceSpan, ...] = Field(min_length=1)


class CompositionGroup(DomainModel):
    group_id: str = Field(min_length=1)
    vulnerability_id: str = Field(pattern=r"^(CVE-[0-9]{4}-[0-9]+|GHSA-[A-Za-z0-9-]+)$")
    operator: Literal["ALL_OF"] = "ALL_OF"
    occurrence_ids: tuple[str, ...] = Field(min_length=2)
