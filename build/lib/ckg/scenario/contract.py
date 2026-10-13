from __future__ import annotations

from pydantic import Field

from ckg.domain.entities.scenario import Scenario
from ckg.domain.value_objects.base import DomainModel


class ScenarioCandidate(DomainModel):
    scenario: Scenario
    premises: tuple[str, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = ()
    missing_bindings: tuple[str, ...] = ()
