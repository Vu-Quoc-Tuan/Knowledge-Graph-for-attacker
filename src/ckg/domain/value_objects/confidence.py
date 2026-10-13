from pydantic import Field, model_validator

from ckg.domain.value_objects.base import DomainModel


class Confidence(DomainModel):
    """Separated confidence dimensions; final score cannot hide missing coverage."""

    relevance: float = Field(ge=0.0, le=1.0)
    evidence_coverage: float = Field(ge=0.0, le=1.0)
    historical_support: float | None = Field(default=None, ge=0.0, le=1.0)
    applicability: float | None = Field(default=None, ge=0.0, le=1.0)
    validation: float | None = Field(default=None, ge=0.0, le=1.0)
    final: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def final_cannot_exceed_coverage_without_explicit_validation(self) -> "Confidence":
        if self.validation is None and self.final > self.evidence_coverage:
            raise ValueError("final confidence cannot exceed evidence coverage without validation")
        return self
