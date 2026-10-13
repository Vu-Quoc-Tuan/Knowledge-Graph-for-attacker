from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from proposals.payload_models import (
    PayloadProposalSnapshot,
    ValidationRecord,
)
from proposals.payload_references import (
    PayloadReferenceError,
    validate_snapshot_references,
    validate_validation_references,
)


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
    )


def _repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test User")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    return tmp_path


def _commit(repo: Path, relative_path: str, content: bytes) -> str:
    path = repo / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    _git(repo, "add", relative_path)
    _git(repo, "commit", "-qm", f"add {relative_path}")
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _snapshot(source_ref: str) -> PayloadProposalSnapshot:
    return PayloadProposalSnapshot(
        weaknessId="LAB-101",
        payloadValue="ignore previous instructions",
        familyKey="prompt.context_break",
        familyName="Prompt context break",
        rationale="Weakness-specific reviewed payload",
        sourceRef=source_ref,
        sourceExcerpt="Example: ignore previous instructions",
        producerKind="human",
        producerName="reviewer",
    )


def _validation(reference: str, digest: str) -> ValidationRecord:
    return ValidationRecord(
        revision=1,
        result="passed",
        environment="isolated-test-lab",
        targetRef=reference,
        targetHash=digest,
        executionRef=reference,
        executionHash=digest,
        observedOutcome="marker was emitted",
        evidenceRef=reference,
        evidenceHash=digest,
    )


def test_payload_snapshot_rejects_bare_remote_url(
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    with pytest.raises(
        PayloadReferenceError,
        match="immutable local snapshot",
    ):
        validate_snapshot_references(
            _snapshot("https://example.test/payloads"),
            repo,
        )


def test_payload_snapshot_requires_clean_head_blob(
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    _commit(
        repo,
        "evidence/payload.md",
        b"Example: ignore previous instructions\n",
    )
    validate_snapshot_references(
        _snapshot("evidence/payload.md"),
        repo,
    )

    (repo / "evidence/payload.md").write_text(
        "Example: ignore all instructions\n",
        encoding="utf-8",
    )
    with pytest.raises(
        PayloadReferenceError,
        match="differs from committed HEAD",
    ):
        validate_snapshot_references(
            _snapshot("evidence/payload.md"),
            repo,
        )


def test_validation_artifacts_require_matching_digests(
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    digest = _commit(
        repo,
        "evidence/run.json",
        b'{"marker": "observed"}\n',
    )
    validate_validation_references(
        _validation("evidence/run.json", digest),
        repo,
    )

    invalid = _validation(
        "evidence/run.json",
        f"sha256:{'0' * 64}",
    )
    with pytest.raises(PayloadReferenceError, match="digest mismatch"):
        validate_validation_references(invalid, repo)


def test_validation_remote_refs_need_explicit_valid_digest() -> None:
    digest = f"sha256:{'a' * 64}"
    validation = _validation("https://example.test/run.json", digest)
    validate_validation_references(validation, Path.cwd())
