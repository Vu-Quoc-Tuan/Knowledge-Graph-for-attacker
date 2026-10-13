# Trustworthy Security Knowledge Pipeline Design

## Goal

Bring the repository in line with the documented five-level trust ladder while
keeping it a knowledge component rather than an attack executor. API and MCP
interfaces are explicitly outside this change.

## Trust ladder

1. **Definition**: a local weakness is queryable from its curated definition.
2. **Relationship**: an accepted `CHILD_OF` or dimensioned `SIMILAR_TO` relation
   supplies scaffolding and references. It does not grant payloads, detection
   signals, or executable scenarios to the local weakness.
3. **Payload**: a payload becomes material for the local weakness only through
   a weakness-specific proposal whose value and excerpt are verified against an
   immutable source snapshot and whose proposal is accepted.
4. **Oracle and scenario**: an executable scenario exists only after the local
   weakness has its own accepted payload material and a reviewed detection
   oracle specification. Reference methodology never satisfies this gate.
5. **Validated material**: validation status is asserted only from a passed
   validation record carrying target, execution, observation, and evidence
   references.

## Relationship scaffolding

`SIMILAR_TO` means that one weakness may inform how material is designed for
another weakness. Its required `dimension` states which part may be adapted:

- `mechanism`: payload shape or context-breaking technique.
- `input_vector`: injection point or delivery path.
- `precondition`: applicability conditions.
- `impact`: the class of observable consequence that may inspire an oracle.
- `detection_strategy`: the validation strategy that may be adapted.

The graph and retrieval layer will distinguish these objects:

- `assertedRelations`: accepted domain relationships and their dimensions,
  rationale, review identity, and evidence references.
- `referenceMethodologies`: methodologies reachable through accepted relations,
  marked `applicability: unknown` and carrying the relation that exposed them.
- `referenceScenarios`: related scenarios offered as design references, marked
  `applicability: unknown`; they are never returned in asserted `scenarios`.
- `scenarios`: only scenarios whose `TARGETS` edge is supported by material
  reviewed specifically for the requested weakness.

The existing automatic scenario inheritance and local scenario copying will be
removed. A future producer may use relation dimensions to draft weakness-specific
payload or oracle proposals, but it must write pending proposals through the
same review workflow; it may not materialize domain facts directly.

## Durable sources and provenance

Local definitions, policies, event logs, source snapshots, and build manifests
are Git-managed durable inputs. Remote advisory ingestion stores the fetched
bytes in a repository-relative snapshot path and records its SHA-256. Payload
proposal evidence must resolve to an immutable local snapshot; an unverified
remote URL is metadata, not byte-exact evidence.

AI payload extraction reads a clean blob committed in `HEAD`. Manual and AI
proposals use the same reference validator so neither path can bypass source
immutability. Validation artifacts may be local committed artifacts or remote
references with an explicit digest; a bare remote URL is insufficient evidence.

Every build writes a source manifest containing source identity, resolved
revision or content digest, retrieval time, and record counts. The manifest
makes provenance and drift visible; an exact replay uses the recorded snapshots
rather than silently fetching newer upstream content.

## Safe materialization

A reset build has two phases:

1. Fetch, snapshot, parse, and validate every required source into an in-memory
   staging graph. Validate minimum invariants and prepare a complete manifest.
2. Only after staging succeeds, replace the Neo4j materialized view from the
   staged graph in one Neo4j write transaction. That transaction deletes the
   old materialized view and replays every staged node and relationship before
   commit. Any deletion, constraint, node, or relationship write failure aborts
   the transaction, so Neo4j rolls back to the complete old graph. This
   transaction-sized replacement is the selected design for the current
   hundred-to-low-thousands-node scale; database/namespace switching is deferred
   until graph size or transaction measurements require it.

HTTP 403, network failure, parse failure, or an incomplete required source fails
the build before deletion. No required stage is converted into an empty success.
Normal non-reset builds continue to reject stale reviewed assertions and report
upstream drift.

## Auditable proposals

Relation proposal snapshots retain retrieval metadata:

- similarity score and score type;
- candidate rank and candidate-set size;
- embedding model/version;
- canonical text hashes;
- relation producer name/version.

The durable event remains the authority for this metadata. Materialized proposal
nodes mirror it for review and metrics such as precision at k. The embedding
score never becomes domain-edge confidence by itself.

An accepted relation may later be withdrawn by a human `retract` event carrying
a mandatory reason. Folding moves the proposal to terminal `retracted` status;
the proposal and full event history remain in the audit layer, while the domain
edge is no longer materialized. Because reference methodologies and scenarios
are computed only through currently materialized accepted edges, they disappear
in the same rebuild and cannot outlive the relation that exposed them.

Payload proposal acceptance continues to require a passed validation record.
Payload identity stays derived from family, technology, and byte-exact value.

## Detection oracle specification

`DetectionSignal` becomes a knowledge contract rather than a label. It includes:

- observable kind (`response`, `timing`, `out_of_band`, `state`, or `execution`);
- observation and success criteria;
- optional baseline/control requirement;
- optional threshold and correlation requirements;
- source, review status, and applicability notes.

Existing PATT-derived signals are explicitly `strategy_hint` until reviewed
criteria exist. This is an intentional trust asymmetry: the ten curated,
authoritative CWE slice scenarios remain test-ready with `strategy_hint`
signals, preserving their current behavior. Only local-weakness scenarios
require an accepted, weakness-specific oracle specification. A strategy hint
may appear on a local reference scenario but cannot make that local weakness's
asserted scenario test-ready.

## Build and repository hygiene

- `.env`, caches, virtual environments, test artifacts, and local Neo4j data are
  ignored before the repository is committed.
- README documents setup, build modes, trust ladder, CLI workflow, limitations,
  source freshness, and consumer semantics.
- The package metadata has a meaningful description.
- The current Linux/POSIX file-lock requirement is explicit. Unsupported
  platforms fail closed instead of silently appending without a lock.

## Tests and acceptance criteria

Tests use `DryRunSink` for unit behavior and the test Neo4j service for parity
where available. Required coverage includes:

- definition-only cards have empty asserted enrichment;
- accepted relations produce references but no inherited asserted scenario;
- each relation dimension preserves its specific adaptation meaning;
- local scenarios require weakness-specific payload and oracle evidence;
- self-relations, duplicate fingerprints, cycles, and invalid transitions fail;
- symmetric fingerprints canonicalize endpoints, so `A SIMILAR_TO B` and
  `B SIMILAR_TO A` produce the same fingerprint for otherwise identical
  proposal metadata;
- multiple accepted `SIMILAR_TO` dimensions merge idempotently;
- source snapshots and hashes are verified for human and AI proposals;
- remote URL-only evidence is rejected;
- newline abridging and append-boundary behavior are covered;
- concurrent appends preserve all valid events on supported POSIX systems;
- reset preflight failure leaves the existing Neo4j graph untouched;
- a successful staged build matches DryRun and Neo4j counts and writes a
  manifest;
- payload acceptance requires a passed validation record;
- retrieval never mixes reference and asserted data.
- withdrawing, rejecting before acceptance, or deprecating the relation that
  exposes a reference removes the corresponding `referenceMethodologies` and
  `referenceScenarios`; references have no independent lifecycle;
- every reference scenario reports the exposing relation predicate, dimension,
  related weakness, rationale, and evidence provenance, matching the metadata
  supplied for reference methodologies.

Completion requires a clean full test run, Python compilation, a successful live
dry-run, and read-only verification of the running Neo4j graph. Destructive live
reset is not part of verification unless separately authorized.

## Non-goals

- No attack execution, payload spraying, or exploit validation runtime.
- No API or MCP server.
- No automatic promotion from AI proposal to asserted domain fact.
- No claim that a relation alone makes a new weakness detectable.
