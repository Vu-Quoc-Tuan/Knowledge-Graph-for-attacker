"""Temporal evaluation protocols that keep frozen and evolving runs distinct."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable


@dataclass(frozen=True)
class DecisionRecord:
    identifier: str
    decision_at: datetime


@dataclass(frozen=True)
class FeedbackRecord:
    identifier: str
    available_at: datetime


@dataclass(frozen=True)
class EvolvingEvaluationStep:
    decision_id: str
    decision_at: datetime
    available_feedback_ids: tuple[str, ...]


def frozen_protocol(decisions: Iterable[DecisionRecord], *, cutoff: datetime) -> tuple[str, ...]:
    """Return held-out decisions without admitting any post-cutoff feedback."""
    return tuple(item.identifier for item in sorted(decisions, key=lambda value: (value.decision_at, value.identifier)) if item.decision_at > cutoff)


def evolving_protocol(
    decisions: Iterable[DecisionRecord], feedback: Iterable[FeedbackRecord], *, cutoff: datetime
) -> tuple[EvolvingEvaluationStep, ...]:
    """Expose only feedback known by each held-out decision time."""
    available = tuple(sorted((item for item in feedback if item.available_at > cutoff), key=lambda value: (value.available_at, value.identifier)))
    return tuple(
        EvolvingEvaluationStep(
            decision_id=decision.identifier,
            decision_at=decision.decision_at,
            available_feedback_ids=tuple(item.identifier for item in available if item.available_at <= decision.decision_at),
        )
        for decision in sorted(decisions, key=lambda value: (value.decision_at, value.identifier))
        if decision.decision_at > cutoff
    )
