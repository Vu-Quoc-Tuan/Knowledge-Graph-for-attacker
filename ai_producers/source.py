from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from utils.git_blobs import GitBlobError, read_committed_utf8


class SourceDocumentError(ValueError):
    """Raised when an AI payload source is not safe and reproducible."""


@dataclass(frozen=True)
class SourceDocument:
    source_ref: str
    relative_path: str
    content: str


def read_tracked_source(
    repo_root: str | Path,
    source_ref: str,
    max_chars: int,
) -> SourceDocument:
    if (
        isinstance(max_chars, bool)
        or not isinstance(max_chars, int)
        or max_chars <= 0
    ):
        raise SourceDocumentError("max_chars must be a positive integer")
    try:
        committed, content = read_committed_utf8(
            Path(repo_root),
            source_ref,
        )
    except GitBlobError as exc:
        raise SourceDocumentError(str(exc)) from exc
    if len(content) > max_chars:
        raise SourceDocumentError(
            f"{source_ref!r}: source exceeds {max_chars} characters"
        )
    return SourceDocument(
        source_ref=source_ref,
        relative_path=committed.relative_path,
        content=content,
    )
