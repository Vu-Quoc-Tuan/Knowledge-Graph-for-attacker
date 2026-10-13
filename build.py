"""Compatibility entrypoint for the canonical v2 build command.

The implementation lives in :mod:`ckg.__main__`; this module intentionally
does not import the legacy sink/build pipeline.
"""

from __future__ import annotations

import sys

from ckg.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main(["build", *sys.argv[1:]]))
