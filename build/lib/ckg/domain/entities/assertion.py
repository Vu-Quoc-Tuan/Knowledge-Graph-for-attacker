from pydantic import Field, model_validator

from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.value_objects.base import DomainModel
from ckg.domain.value_objects.confidence import Confidence
from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.domain.value_objects.provenance import Provenance


class _Assertion(DomainModel):
    assertion_id: str = Field(min_length=1)
    status: FactStatus
    provenance: Provenance
    evidence_spans: tuple[EvidenceSpan, ...] = Field(min_length=1)
    confidence: Confidence | None = None
    relevance: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def status_and_origin_are_coherent(self) -> "_Assertion":
        if self.status == FactStatus.CANONICAL and self.provenance.source_kind != "mitre":
            raise ValueError("only MITRE source records may be canonical assertions")
        return self


class WeaknessAssertion(_Assertion):
    vulnerability_id: str = Field(pattern=r"^(CVE-[0-9]{4}-[0-9]+|GHSA-[A-Za-z0-9-]+)$")
    cwe_id: str = Field(pattern=r"^CWE-[0-9]+$")
    role: str = Field(default="primary", min_length=1)


class TechniqueAssertion(_Assertion):
    vulnerability_id: str = Field(pattern=r"^(CVE-[0-9]{4}-[0-9]+|GHSA-[A-Za-z0-9-]+)$")
    technique_id: str = Field(min_length=1)
    relation: str = Field(min_length=1)
