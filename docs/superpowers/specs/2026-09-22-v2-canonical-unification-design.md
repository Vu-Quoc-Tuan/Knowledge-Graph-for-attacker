# V2 Canonical Runtime Unification Design

## Goal

Make the provenance-first `ckg` v2 implementation the only runtime, graph
storage contract, build path, and web UI source of truth while preserving
legacy graph data and providing explicit one-way migration tooling.

## Decision

`CKGApplication` plus `GraphRepository` is the only application runtime
contract. `ckg build`, `ckg serve`, and the packaged UI under
`src/ckg/ui/v2/` are the only first-class entrypoints and assets.

The old `ui/server.py` and root `build.py` names remain only as compatibility
entrypoints. They delegate to v2 and must not instantiate `Settings`,
`GraphSink`, `Neo4jSink`, `DryRunSink`, or legacy route handlers. Legacy
registry/event modules remain available only for explicit migration commands;
they do not create a second runtime graph.

## Scope

### Runtime and storage

- Add a shared v2 repository/application factory so CLI, compatibility
  wrappers, tests, and scripts select the same `InMemoryGraphRepository` or
  `Neo4jGraphRepository` implementation.
- Keep Neo4j configuration in the v2 settings/env path and reject accidental
  use of the old sink configuration from runtime entrypoints.
- Make the v2 graph schema identity explicit in health/status responses.
- Keep migration adapters separate from normal build/serve code.

### Entry points

- Make the existing v2 `ckg build` implementation support the documented
  manifest/reset/dry-run options needed by the old build workflow.
- Replace root `build.py` with a small argument-preserving delegator to
  `ckg.__main__.main(["build", ...])`.
- Replace root `ui/server.py` with a small delegator to the v2 server and keep
  only a clearly named compatibility `main()` path.
- Update Makefile, README, scripts, and tests to invoke v2 commands directly
  where no compatibility behavior is required.

### UI assets

- Keep `src/ckg/ui/v2/` as the only maintained UI asset tree.
- Serve packaged/source-tree assets from that location without a root `ui/v2`
  fallback.
- Remove package-data declarations and tests that treat root `ui/v2` as a
  second asset source.
- Add a packaging/runtime test that the installed wheel serves the same UI
  contract as the source checkout.

### Migration and compatibility

- Keep `src/ckg/migration/legacy_registry.py` and
  `src/ckg/migration/legacy_vulnerability_events.py` as explicit one-way
  adapters into `GraphRepository`.
- Preserve legacy event/registry files and graph data; no destructive delete or
  implicit rewrite occurs during normal `ckg serve` or `ckg build`.
- Keep legacy producer/domain modules only where they are still needed for
  migration or offline compatibility tests, but prevent them from being
  selected by the v2 runtime.
- Update documentation so that a legacy command is clearly a delegator or a
  migration operation, not an alternate product workflow.

## Non-goals

- This change does not silently transform already materialized legacy Neo4j
  nodes in place.
- This change does not delete legacy source files, event logs, registry files,
  or graph data merely to make the repository look smaller.
- This change does not claim live Neo4j acceptance without running the Neo4j
  test profile and the v2 integration suite against it.

## Data flow

```text
ckg build / build.py wrapper ─┐
ckg serve / ui/server wrapper ├─> v2 repository factory
tests and scripts ────────────┘          ├─> InMemoryGraphRepository
                                         └─> Neo4jGraphRepository
                                                  └─> CKGApplication
                                                       └─> src/ckg/ui/v2

legacy registry/event files ──explicit migrate command──> GraphRepository
```

There is no normal runtime path from `ui/server.py` to `db.sink`, and no
normal runtime path from v2 to a legacy schema. The only cross-boundary path
is an explicit migration adapter with a report and idempotency checks.

## Error handling

- Compatibility wrappers return the delegated v2 exit code and preserve the
  delegated exception/diagnostic text.
- The UI fails closed if the packaged UI asset is missing rather than silently
  switching to a second asset tree.
- Migration commands fail closed on missing snapshots, invalid digests,
  incompatible identities, or partial writes.
- No fallback from a failed Neo4j v2 connection to a legacy sink is allowed.

## Verification criteria

1. `ckg --help`, `ckg build --help`, and `ckg serve --help` expose the v2
   commands without importing legacy sink/server modules.
2. `build.py --help` delegates to the same v2 parser and does not import
   `db.sink`.
3. `ui/server.py` delegates to the same v2 server and does not import
   `config`, `db.sink`, legacy `ingest`, legacy `proposals`, or `retrieval`.
4. Source and wheel UI tests use only `src/ckg/ui/v2/` and the technology to
   CVE flow still works.
5. Migration tests continue to prove idempotent, provenance-preserving
   legacy-to-v2 conversion.
6. The full suite passes in a permitted execution context; Neo4j tests are
   reported separately when the test service is unavailable.
7. `git diff --check`, bytecode compilation, and wheel build pass.
