from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_build_module_is_a_v2_delegator() -> None:
    source = Path("build.py").read_text(encoding="utf-8")
    assert "db.sink" not in source
    assert "ckg.__main__" in source


def test_v2_build_help_exposes_compatibility_flags() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ckg", "build", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--dry-run" in result.stdout
    assert "--reset" in result.stdout
