# V2 Canonical Runtime Unification — Completed Record

Status: completed and verified on 2026-09-22.

The repository now has one maintained runtime contract:

- `ckg build` stages canonical CWE/CAPEC data and explicit legacy migration
  adapters into the v2 graph contract.
- `ckg serve` exposes the v2 API and the packaged UI under `src/ckg/ui/v2/`.
- Root `build.py` and `ui/server.py` are compatibility delegators only.
- `InMemoryGraphRepository` and `Neo4jGraphRepository` implement the same v2
  repository boundary; legacy sinks are not runtime fallbacks.
- `src/ckg/migration/legacy_registry.py` and
  `src/ckg/migration/legacy_vulnerability_events.py` remain explicit,
  one-way migration adapters.
- The source and package scenario catalogs are synchronized, and their
  user-facing text is loaded from the catalog `templates` section.

Verification evidence for this record:

- `.venv/bin/python -m pytest -q -rs` — 222 passed, 1 warning.
- `python3 -m py_compile $(rg --files -g '*.py')` — passed.
- `ckg build --dry-run` — completed with the expected canonical graph counts.
- `scripts.verify_canonical_catalogs` and
  `scripts.verify_legacy_v2_migration` — completed with explicit diagnostic
  summaries; unresolved source-release references remain non-promotable.
- CLI, `/healthz`, `/ui/v2/`, and technology/year CVE search smoke checks —
  completed against the in-memory server.

The historical design details are preserved in git history. This file is a
completion record, not an active unchecked implementation checklist.
