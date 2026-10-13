"""Normalize context values through explicit aliases; unknown values abstain."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedContext:
    context_id: str
    kind: str
    name: str


_KNOWN_CONTEXTS = {
    "python": NormalizedContext("LANG-PYTHON", "Language", "Python"),
    "java": NormalizedContext("LANG-JAVA", "Language", "Java"),
    "xml": NormalizedContext("FORMAT-XML", "DataFormat", "XML"),
    "json": NormalizedContext("FORMAT-JSON", "DataFormat", "JSON"),
    "http": NormalizedContext("PROTOCOL-HTTP", "Protocol", "HTTP"),
    "dns": NormalizedContext("PROTOCOL-DNS", "Protocol", "DNS"),
}


def normalize_context(value: str) -> NormalizedContext | None:
    return _KNOWN_CONTEXTS.get(" ".join(value.lower().split()))
