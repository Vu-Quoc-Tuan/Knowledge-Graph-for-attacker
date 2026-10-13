from pydantic import Field

from ckg.domain.value_objects.base import DomainModel


class ContextFacet(DomainModel):
    context_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    name: str = Field(min_length=1)
    aliases: tuple[str, ...] = ()
