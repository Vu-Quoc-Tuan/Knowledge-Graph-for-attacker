"""Offline v2 profile rebuild; caller selects the repository implementation."""

from __future__ import annotations

import argparse

from ckg.evolution.cooccurrence import mine_cooccurrence
from ckg.evolution.cwe_profiler import rebuild_cwe_profiles
from ckg.graph.memory import InMemoryGraphRepository


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild v2 learned profiles in an explicitly supplied application context")
    parser.add_argument("--dry-run", action="store_true", help="Construct an empty in-memory repository to validate wiring only")
    args = parser.parse_args()
    if not args.dry_run:
        parser.error("this script deliberately refuses an implicit live database; invoke application services with an explicit repository")
    repository = InMemoryGraphRepository()
    print({"profiles": rebuild_cwe_profiles(repository).__dict__, "cooccurrence": mine_cooccurrence(repository).__dict__})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
