"""Candidate link prediction is deliberately deferred to an explicit inference producer."""

from ckg.domain.enums.fact_status import FactStatus


def initial_status() -> FactStatus:
    return FactStatus.INFERRED
