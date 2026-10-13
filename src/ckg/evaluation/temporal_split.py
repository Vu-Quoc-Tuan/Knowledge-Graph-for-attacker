from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable


@dataclass(frozen=True)
class TemporalSplit:
    train_ids: tuple[str, ...]
    test_ids: tuple[str, ...]
    excluded_ids: tuple[str, ...]


def temporal_split(records: Iterable[tuple[str, datetime | None]], *, cutoff: datetime) -> TemporalSplit:
    train, test, excluded = [], [], []
    for identifier, known_at in records:
        if known_at is None:
            excluded.append(identifier)
        elif known_at <= cutoff:
            train.append(identifier)
        else:
            test.append(identifier)
    return TemporalSplit(tuple(sorted(train)), tuple(sorted(test)), tuple(sorted(excluded)))
