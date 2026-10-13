"""Strict content-address validation for externally supplied source snapshots."""

from __future__ import annotations

import hashlib
import re


def sha256_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def verify_snapshot_digest(content: bytes, expected: str) -> None:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        raise ValueError(f"invalid source snapshot digest: {expected!r}")
    actual = sha256_digest(content)
    if actual != expected:
        raise ValueError(f"source snapshot digest mismatch: expected {expected}, got {actual}")
