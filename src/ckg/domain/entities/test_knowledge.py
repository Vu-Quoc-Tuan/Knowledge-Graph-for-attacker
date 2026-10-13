from pydantic import Field

from ckg.domain.value_objects.base import DomainModel


class TestStrategy(DomainModel):
    __test__ = False

    strategy_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    source_kind: str = Field(min_length=1)


class WSTGCase(DomainModel):
    wstg_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    source_release: str = Field(min_length=1)
    source_snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ProbeFamily(DomainModel):
    probe_family_id: str = Field(min_length=1)
    name: str = Field(min_length=1)


class BypassTechnique(DomainModel):
    bypass_id: str = Field(min_length=1)
    name: str = Field(min_length=1)


class Oracle(DomainModel):
    oracle_id: str = Field(min_length=1)
    name: str = Field(min_length=1)


class InputSurface(DomainModel):
    input_surface_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
