"""Read immutable evidence from the clean blob committed at ``HEAD``."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


class GitBlobError(ValueError):
    """A repository reference is not a reproducible committed blob."""


@dataclass(frozen=True)
class CommittedSourceRef:
    source_ref: str
    relative_path: str
    content: bytes
    sha256: str

    def utf8(self) -> str:
        try:
            return self.content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitBlobError(
                f"{self.source_ref!r}: source is not valid UTF-8"
            ) from exc


def _run_git(
    root: Path,
    arguments: list[str],
    *,
    error: str,
    text: bool = False,
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            text=text,
            encoding="utf-8" if text else None,
            errors="replace" if text else None,
        )
    except (OSError, ValueError) as exc:
        raise GitBlobError(f"{error}: cannot run Git") from exc
    if result.returncode != 0:
        raise GitBlobError(error)
    return result


def git_worktree_root(start: str | Path) -> Path:
    candidate = Path(start).resolve()
    if candidate.is_file():
        candidate = candidate.parent
    result = _run_git(
        candidate,
        ["rev-parse", "--show-toplevel"],
        error=f"{candidate}: not a Git worktree",
        text=True,
    )
    return Path(result.stdout.strip()).resolve()


def _relative_reference(source_ref: str) -> PurePosixPath:
    parsed = urlsplit(source_ref)
    if parsed.scheme or parsed.netloc:
        raise GitBlobError(
            f"{source_ref!r}: reference must be an immutable local snapshot"
        )
    if parsed.query:
        raise GitBlobError(
            f"{source_ref!r}: local reference must not contain a query"
        )
    pure = PurePosixPath(parsed.path)
    if not parsed.path or pure.is_absolute() or ".." in pure.parts:
        raise GitBlobError(
            f"{source_ref!r}: reference must stay inside the repository"
        )
    return PurePosixPath(*pure.parts)


def read_committed_blob(
    repo_root: str | Path,
    source_ref: str,
) -> CommittedSourceRef:
    root = Path(repo_root).resolve()
    if git_worktree_root(root) != root:
        raise GitBlobError(
            f"{root}: repo_root must be the Git worktree root"
        )

    pure = _relative_reference(source_ref)
    relative_path = pure.as_posix()
    unresolved = root / Path(*pure.parts)
    try:
        resolved = unresolved.resolve()
    except (OSError, RuntimeError) as exc:
        raise GitBlobError(
            f"{source_ref!r}: cannot resolve source path"
        ) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise GitBlobError(
            f"{source_ref!r}: source escapes the repository"
        ) from exc
    if resolved != unresolved.absolute():
        raise GitBlobError(
            f"{source_ref!r}: source symlinks are not allowed"
        )
    if not resolved.is_file():
        raise GitBlobError(
            f"{source_ref!r}: source file does not exist"
        )

    _run_git(
        root,
        ["ls-files", "--error-unmatch", "--", relative_path],
        error=f"{source_ref!r}: source is not tracked by Git",
    )
    _run_git(
        root,
        ["cat-file", "-e", f"HEAD:{relative_path}"],
        error=f"{source_ref!r}: source is not committed in HEAD",
    )
    _run_git(
        root,
        ["diff", "--quiet", "HEAD", "--", relative_path],
        error=f"{source_ref!r}: source differs from committed HEAD",
    )
    content = _run_git(
        root,
        ["cat-file", "blob", f"HEAD:{relative_path}"],
        error=f"{source_ref!r}: cannot read committed Git blob",
    ).stdout
    digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
    return CommittedSourceRef(
        source_ref=source_ref,
        relative_path=relative_path,
        content=content,
        sha256=digest,
    )


def read_committed_utf8(
    repo_root: str | Path,
    source_ref: str,
) -> tuple[CommittedSourceRef, str]:
    committed = read_committed_blob(repo_root, source_ref)
    return committed, committed.utf8()
