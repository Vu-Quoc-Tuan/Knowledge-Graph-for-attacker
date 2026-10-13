from pydantic import Field

from ckg.domain.enums.applicability import Applicability
from ckg.domain.value_objects.base import DomainModel


class ApplicabilityConstraint(DomainModel):
    constraint_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    expression: str = Field(min_length=1)


class ConstraintEvaluation(DomainModel):
    constraint_id: str = Field(min_length=1)
    applicability: Applicability
    rationale: str = Field(min_length=1)
