from datetime import datetime

from pydantic import Field

from ckg.domain.value_objects.base import DomainModel
from ckg.domain.value_objects.provenance import Provenance


class AttackPattern(DomainModel):
    capec_id: str = Field(pattern=r"^CAPEC-[0-9]+$")
    name: str = Field(min_length=1)
    source_release: str = Field(min_length=1)
    source_snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    retrieved_at: datetime | None = None
    description: str | None = None


class CAPECWeaknessRelation(DomainModel):
    relation_id: str = Field(min_length=1)
    capec_id: str = Field(pattern=r"^CAPEC-[0-9]+$")
    cwe_id: str = Field(pattern=r"^CWE-[0-9]+$")
    provenance: Provenance


class AttackStep(DomainModel):
    step_id: str = Field(min_length=1)
    capec_id: str = Field(pattern=r"^CAPEC-[0-9]+$")
    ordinal: int = Field(ge=1)
    phase: str | None = None
    description: str = Field(min_length=1)
    retrieved_at: datetime | None = None


class AttackPrerequisite(DomainModel):
    prerequisite_id: str = Field(min_length=1)
    capec_id: str = Field(pattern=r"^CAPEC-[0-9]+$")
    ordinal: int = Field(ge=1)
    description: str = Field(min_length=1)
    retrieved_at: datetime | None = None
