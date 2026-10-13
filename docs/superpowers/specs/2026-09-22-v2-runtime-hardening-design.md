# V2 Runtime Hardening Design

## Scope

This change hardens the canonical v2 runtime and the technology-to-CVE search
without changing credential handling, the default Neo4j password, or API
authentication. Those three concerns are explicitly deferred.

## Goals

1. Make the UI describe the actual selected backend and report partial request
   failures instead of claiming a complete load.
2. Remove the misleading Cypher console from the public UI.
3. Make technology-to-CVE search reproducible, bounded, ranked, paginated, and
   semantically aligned between the in-memory and Neo4j repositories.
4. Preserve original CPE/product identity and expose truncation/source metadata.
5. Make unresolved catalog references and missing migration evidence explicit,
   without inventing graph facts or silently promoting unverifiable evidence.
6. Add regression coverage for the above and document the live Neo4j parity
   command.

## Non-goals

- Rotating or removing secrets in `.env`.
- Removing `change-me-please` defaults.
- Adding authentication or authorization to the HTTP API.
- Replacing the dependency-light HTTP server with a web framework.
- Deleting the explicit legacy migration adapters.

## Design

### HTTP and UI

The API handler will enforce a configurable maximum request body size before
JSON parsing and return a stable generic server error message while logging the
internal exception locally. The UI will remove the generated Cypher panel and
copy action. Case loading will collect the status of every requested resource;
the case file remains the primary success condition, while failures of
neighbors, scenarios, or subgraph are rendered as a visible partial warning.
The success notice will use the backend identity returned by `/healthz`.

### Technology search

The `Product` node keeps canonical searchable fields plus the original CPE
criterion when one exists. Search results include a deterministic relevance
score and match reasons. Both repository implementations use the same matching
rules: normalized name/vendor/package aliases, exact/word-prefix preference,
year filtering, source-state filtering, CVE/GHSA folding, stable ordering, and
bounded pagination. The API response reports `total`, `returned`, `offset`,
`limit`, `truncated`, and the source/snapshot metadata available for the
returned records.

The NVD refresh path retains the configured maximum-record bound and reports
when the upstream result was truncated; it does not pretend that a bounded
fetch is exhaustive.

### Provenance and catalog diagnostics

Verifier output will distinguish unresolved membership references by reason and
will keep them outside canonical relation assertions until their target is
resolved. Migration reports will distinguish missing local snapshot artifacts
from invalid evidence and will keep those evidence IDs unverifiable. Existing
fail-closed reasoning gates remain authoritative.

### Testing

Add unit tests for normalization, scoring, pagination, truncation, unresolved
diagnostics, and evidence gating. Add API tests for request-size rejection and
stable errors. Add browser smoke assertions for the absence of the Cypher
panel, backend-aware notice, technology result navigation, and partial-load
warnings. Keep live Neo4j tests opt-in and document the required test service;
the in-memory suite must not be treated as Neo4j parity proof.

