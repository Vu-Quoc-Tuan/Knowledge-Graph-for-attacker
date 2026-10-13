"""Deterministic local lexical baseline; production embedding adapter is versioned later."""

from __future__ import annotations

import hashlib
import re


def lexical_embedding(text: str, *, dimensions: int = 64) -> tuple[float, ...]:
    values = [0.0] * dimensions
    for token in re.findall(r"[a-z0-9]{2,}", text.lower()):
        values[int(hashlib.sha256(token.encode()).hexdigest(), 16) % dimensions] += 1.0
    norm = sum(value * value for value in values) ** 0.5
    return tuple(value / norm for value in values) if norm else tuple(values)
