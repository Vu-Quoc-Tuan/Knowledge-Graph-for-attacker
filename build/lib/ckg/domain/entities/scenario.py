from pydantic import Field

from ckg.domain.enums.applicability import Applicability
from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.enums.scenario_type import ScenarioType
from ckg.domain.value_objects.base import DomainModel
from ckg.domain.value_objects.confidence import Confidence


class Scenario(DomainModel):
    scenario_id: str = Field(min_length=1)
    schema_version: int = Field(default=1, ge=1)
    scenario_type: ScenarioType
    status: FactStatus
    target_vulnerability_id: str = Field(pattern=r"^(CVE-[0-9]{4}-[0-9]+|GHSA-[A-Za-z0-9-]+)$")
    weakness_ids: tuple[str, ...] = Field(min_length=1)
    technique_ids: tuple[str, ...] = ()
    channel_ids: tuple[str, ...] = ()
    context_ids: tuple[str, ...] = ()
    oracle_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    applicability: Applicability
    confidence: Confidence
    derivation_ids: tuple[str, ...] = Field(min_length=1)
    missing_bindings: tuple[str, ...] = ()
    title: str = ""
    description: str = ""
    steps: tuple[str, ...] = ()
    poc_command: str = ""
