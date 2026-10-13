# Provenance and Temporal Remediation Design

## Goal

Make scenario promotion, feedback, source extraction, revision handling, and
historical retrieval evidence-faithful.  The system must fail closed rather
than represent unexecuted, synthetic, stale, or context-incompatible data as
validated CVE knowledge.

## Scope and non-goals

This remediation covers the nineteen review findings in the 2026-09-19
review: the P1 promotion/provenance/context/idempotency/revision defects and
the P2 temporal/catalog/sandbox/multi-weakness defects.

It preserves raw source history, legacy API compatibility where it does not
misrepresent trust, and synthetic sandbox capability for demo/protocol tests.
It does not claim live target-CVE reproduction, introduce live Neo4j/browser
acceptance, or delete existing graph history.

## Design

### 1. Validation and execution provenance

`incremental_materialize_scenario` will validate before writing.  A promotion
requires a passed record, matching candidate/scenario and target IDs, a
non-empty execution/evidence digest, and a resolvable immutable artifact.  A
failed, mismatched, absent, or synthetic record cannot set `testReady`,
`detectionSignalStatus=accepted`, or a validated relationship.

The legacy materialize endpoint will require a supplied receipt; it will not
synthesize one from scenario steps.  The ephemeral runner remains available
as a `synthetic` execution mode.  It persists a request/response artifact
bundle before returning its receipt and its receipt cannot be promoted to
target-CVE validation.  Its differential oracle uses an HTML-significant
canary and verifies both raw vulnerable reflection and non-raw patched output.

### 2. Evidence grounding and feedback

Model extraction may create an evidence span only for an exact source quote or
a sentence-local supported span.  A non-matching quote yields abstention; a
single overlapping word must not license the complete source text.

Analysis obtains description text and locator/digest from the same current
source-record revision.  Feedback verifies immutable execution evidence,
artifact existence/digest, permitted evidence kind, scenario revision, and
environment linkage before deriving quality and scope.  Caller flags cannot
turn an advisory into execution evidence.

### 3. Current and historical projections

CVE source records and canonical catalog content are immutable revisions.
Current projections select the newest eligible revision per source identity;
withdrawn/rejected records suppress current derived enrichment and supersede
their same-source claims without erasing independent sources.

Re-importing identical canonical bytes preserves the original content
availability time and records fetch/replay metadata separately.  Catalog edges
are release-scoped and retrieval selects only edges effective at `current` or
the requested `as_of` cutoff.  The same node and edge visibility predicate is
used by historical candidate retrieval, local subgraph construction, and CLI
analysis.  `--as-of` is a read cutoff, never a write timestamp.

Posterior state is represented by immutable observation/revision history (or
replayed as of the cutoff), not an overwritten aggregate.  A later observation
cannot alter an earlier query result.

### 4. Contextual discovery and catalog correctness

Posterior application receives the target scenario's full environment scope
(weakness, runtime, libraries, configuration, and revision) and only applies
compatible buckets.  Inheritance excludes same-target scenarios and rejects
cycles in lineage.  Discovery consequently remains idempotent on unchanged
input.

Weaknesses are grouped by catalog category.  Synthesis creates a separate
candidate for each group and attaches only that group; chain/composite paths
continue to require their own evidence.  The scenario catalog is packaged as
`ckg` package data and loaded via package resources, so installed and editable
runtimes behave identically.

## Implementation order and acceptance tests

1. Add failing regressions for materialization, synthetic receipt promotion,
   fabricated quotes, same-target inheritance, and rejected enrichment; then
   implement the fail-closed P1 contracts.
2. Add regressions for evidence binding, feedback artifact/revision checks,
   full scope matching, CVE current projection, and posterior history; then
   make revisions/projections explicit.
3. Add temporal edge/cutoff, canonical relationship/replay, CLI `as_of`,
   packaged catalog, multi-weakness, and sandbox artifact/oracle regressions;
   then update their consumers.
4. Run focused tests at each step, followed by the repository suite.  A test
   result is not evidence of live target-CVE validation; that requires a real
   target-specific harness and artifact review.

## Safety invariants

- Only verified non-synthetic execution evidence can be represented as target
  validation.
- A fact's source bytes, revision, digest, locator, and known time agree.
- Unknown, failed, withdrawn, synthetic, and mismatched records never upgrade
  trust.
- Historical decisions see no nodes, edges, evidence, or posterior data known
  after their cutoff.
- Replaying unchanged source input or discovery input does not create new
  scenarios or mutate historical outcomes.

## Open runtime boundary

Unit and memory-graph tests will establish the code contracts.  Live Neo4j and
browser/API acceptance remain separate checks and will only be claimed if they
are run against an isolated environment.
