"""Shared environment-file loading for every CKG application surface."""

from __future__ import annotations

import os
from pathlib import Path


def load_env(path: str | Path | None = None) -> None:
    """Load a dotenv-style file without overwriting explicit environment values."""
    if path is not None:
        candidates = [Path(path)]
    else:
        candidates = [
            Path.cwd() / ".env",
            Path(__file__).resolve().parents[3] / ".env",
        ]
    env_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if env_path is None:
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))
