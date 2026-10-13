"""Small, lossless-enough unified-diff parser for evidence locator creation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DiffHunk:
    ordinal: int
    header: str
    added_lines: tuple[str, ...]
    removed_lines: tuple[str, ...]


def parse_unified_diff(value: str) -> tuple[DiffHunk, ...]:
    hunks: list[DiffHunk] = []
    header: str | None = None
    added: list[str] = []
    removed: list[str] = []
    for line in value.splitlines():
        if line.startswith("@@"):
            if header is not None:
                hunks.append(DiffHunk(len(hunks), header, tuple(added), tuple(removed)))
            header, added, removed = line, [], []
        elif header is not None and line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif header is not None and line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    if header is not None:
        hunks.append(DiffHunk(len(hunks), header, tuple(added), tuple(removed)))
    return tuple(hunks)
