from datetime import datetime
from enum import StrEnum

from pydantic import Field

from ckg.domain.value_objects.base import DomainModel


class ObservationResult(StrEnum):
    REPRODUCED = "REPRODUCED"
    NO_SIGNAL = "NO_SIGNAL"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class ExecutionObservation(DomainModel):
    observation_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    scenario_revision: int = Field(default=1, ge=1)
    environment_id: str = Field(min_length=1)
    result: ObservationResult
    observed_at: datetime
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    evidence_digests: tuple[str, ...] = Field(min_length=1)
