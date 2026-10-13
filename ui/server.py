"""Compatibility entrypoint for the canonical v2 CKG server.

The application implementation lives in :mod:`ckg.api.main`. This module is
kept only so existing ``python ui/server.py`` invocations follow the same v2
server path as ``ckg serve``.
"""

from __future__ import annotations

import sys

from ckg.__main__ import main as ckg_main


def run_server(port: int = 8088, host: str = "127.0.0.1") -> int:
    """Run the canonical v2 server with the historical function signature."""

    return ckg_main(["serve", "--host", host, "--port", str(port)])


def main(argv: list[str] | None = None) -> int:
    """Delegate command-line arguments to the canonical v2 serve command."""

    return ckg_main(["serve", *(sys.argv[1:] if argv is None else argv)])


if __name__ == "__main__":
    raise SystemExit(main())
