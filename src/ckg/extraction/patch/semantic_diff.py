"""Stable semantic clues from changed lines; no source-code execution or AST guesswork."""

from __future__ import annotations

from ckg.extraction.patch.diff_parser import DiffHunk


def added_text(hunk: DiffHunk) -> str:
    return "\n".join(hunk.added_lines).lower()
