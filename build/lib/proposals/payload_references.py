"""Validate durable payload evidence without fetching or executing it."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from proposals.payload_models import (
    PayloadProposalSnapshot,
    ValidationRecord,
)
from utils.git_blobs import GitBlobError, read_committed_blob


class PayloadReferenceError(ValueError):
    """A payload evidence reference is unsafe or cannot be verified."""


def _remote_reference(
    field: str,
    reference: str,
) -> bool:
    parsed = urlsplit(reference)
    if parsed.scheme in {"http", "https"}:
        if not parsed.netloc:
            raise PayloadReferenceError(
                f"{field} {reference!r}: remote reference must "
                "be an absolute http/https URL"
            )
        return True
    if parsed.scheme:
        raise PayloadReferenceError(
            f"{field} {reference!r}: unsupported reference scheme"
        )

    return False


def validate_snapshot_references(
    snapshot: PayloadProposalSnapshot,
    repo_root: str | Path,
) -> None:
    if _remote_reference("sourceRef", snapshot.sourceRef):
        raise PayloadReferenceError(
            f"sourceRef {snapshot.sourceRef!r}: payload extraction "
            "requires an immutable local snapshot"
        )
    try:
        source = read_committed_blob(
            Path(repo_root),
            snapshot.sourceRef,
        ).utf8()
    except GitBlobError as exc:
        raise PayloadReferenceError(str(exc)) from exc
    if snapshot.sourceExcerpt not in source:
        raise PayloadReferenceError(
            f"sourceRef {snapshot.sourceRef!r}: "
            "local source does not contain sourceExcerpt"
        )


def validate_validation_references(
    validation: ValidationRecord,
    repo_root: str | Path,
) -> None:
    root = Path(repo_root)
    for field, hash_field in (
        ("targetRef", "targetHash"),
        ("executionRef", "executionHash"),
        ("evidenceRef", "evidenceHash"),
    ):
        reference = getattr(validation, field)
        expected_hash = getattr(validation, hash_field)
        if _remote_reference(field, reference):
            continue
        try:
            committed = read_committed_blob(root, reference)
        except GitBlobError as exc:
            raise PayloadReferenceError(str(exc)) from exc
        if committed.sha256 != expected_hash:
            raise PayloadReferenceError(
                f"{field} {reference!r}: digest mismatch; "
                f"expected {expected_hash}, got {committed.sha256}"
            )
