# Security and architecture hardening

## Scope

Implement the confirmed security, reliability, and configuration findings from the repository review while preserving the existing worktree changes. Keep legacy and v2 graph schemas explicitly separated until a provenance-safe migration is designed; do not silently merge incompatible node/edge contracts.

## Work items

1. Remove the UI password disclosure and tighten public Cypher access.
2. Replace Neo4j autocommit writes and production asserts; close schema files safely.
3. Make configuration failures visible, remove the implicit model fallback, and make scenario-catalog initialization thread-safe.
4. Add cross-platform proposal locking and bounded embedding-cache eviction.
5. Make UI version/CORS/backend selection explicit and remove the production test-port probe.
6. Reduce UI routing concentration through route modules without changing endpoint contracts.
7. Add focused regression coverage and distinguish sandbox/network permission failures from code failures.

## Deliberate boundary

The legacy sink graph and v2 repository use incompatible schemas. A safe fix needs a migration/cutover contract and target-graph validation; this pass adds explicit schema identity/guardrails rather than duplicating writes or pretending the stores are consistent.
