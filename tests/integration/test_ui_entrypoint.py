from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_ui_server_is_a_v2_delegator() -> None:
    source = Path("ui/server.py").read_text(encoding="utf-8")
    for forbidden in ("config", "db.sink", "from ingest", "from proposals", "from retrieval"):
        assert forbidden not in source
    assert "ckg.__main__" in source


def test_ui_server_help_uses_v2_parser() -> None:
    result = subprocess.run(
        [sys.executable, "ui/server.py", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "ckg serve" in result.stdout
    assert "--host" in result.stdout
    assert "--port" in result.stdout
