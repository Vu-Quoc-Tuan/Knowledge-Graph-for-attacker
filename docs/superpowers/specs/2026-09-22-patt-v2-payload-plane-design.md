# PATT Raw Payload Plane for Canonical V2

## Goal

Import the ten existing PayloadsAllTheThings (PATT) slices into the canonical
v2 `GraphRepository` as source-backed payload references.  The result must be
queryable through the v2 API and visible in the v2 case-file UI without
claiming that an upstream payload is validated against any target.

## Scope

The importer covers the current curated slice set:

- `CWE-89`: SQL injection;
- `CWE-79`: cross-site scripting;
- `CWE-78`: command injection;
- `CWE-918`: server-side request forgery;
- `CWE-22`: path traversal;
- `CWE-434`: insecure file upload;
- `CWE-352`: cross-site request forgery;
- `CWE-94`: server-side template injection;
- `CWE-502`: insecure deserialization; and
- `CWE-93`: CRLF injection.

The import action is explicit.  `ckg build`, graph read endpoints, and the UI
must never initiate a PATT network fetch.  A user may import PATT from a local
snapshot or through a deliberate CLI fetch action.

This work does not add target execution, automatic validation, API
authentication, a generic import of every PATT directory, or a paper benchmark
for payload retrieval.

## Existing Code and Migration Boundary

`ingest/patt_loader.py` already has mature extraction rules for PATT fenced
blocks, Markdown table code, technology filenames, per-family caps, and Burp
Intruder wordlists.  It currently materializes the legacy `GraphSink` schema.

The new v2 implementation must move or share the pure parsing rules without
making canonical runtime code depend on `db.sink`, `schema.models`, or the
legacy build path.  The old loader becomes a compatibility caller of the shared
parser where practical; it is not a second v2 graph writer.

The existing v2 PATT methodology importer remains responsible for
`PATTDocument`, `PATTSection`, `Technique`, `CallbackChannel`,
`ProbeFamily`, `BypassTechnique`, and `Evidence`.  It must continue to avoid
creating payload nodes merely because code-like text appears in a document.
The raw-payload importer is a separate, explicit projection that consumes the
same snapshot-backed document data.

## Data Model

The v2 payload plane uses normal `GraphNode` and `GraphEdge` values under the
existing `GraphRepository` contract.

### Nodes

`PayloadFamily` contains:

- stable `family_key` and human-readable name;
- the mapped CWE ID;
- optional detection signal;
- provenance identifying PATT as the source catalog.

The exact payload candidates are not graph nodes. They are stored in the
snapshot-backed `PATTIndex` SQLite sidecar with stable `payload_id`,
byte-exact `value`, SHA-256 `payload_digest`, family, optional technology,
source document/file, source revision, snapshot digest, section heading,
locator, extraction kind, `origin="patt"`,
`curation_status="upstream_curated"`, and `validation_status="untested"`.

The staging importer keeps `Technology`, `PATTDocument`, `PayloadFamily`, and
`Evidence` nodes long enough to preserve source relationships. The focused
active graph keeps only `PayloadFamily` and `Technology`; documents, PATT
evidence, and their relationships are exported losslessly to
`compact_details.sqlite3`. The separate methodology importer may retain
bounded `PATTSection` nodes for technique locators, but the raw payload
importer never creates one-node-per-section or one-node-per-payload
expansions. Importing the same snapshot is idempotent.

### Edges

The importer writes only these source-backed relations:

```text
CWE           -[HAS_PAYLOAD_FAMILY]-> PayloadFamily
PayloadFamily -[SOURCED_FROM]-> PATTDocument
PATTDocument  -[SUPPORTED_BY]-> Evidence
PayloadFamily -[APPLIES_TO]-> Technology              (when payload evidence exists)
```

No import edge directly connects a CVE/GHSA to a raw PATT payload.  No imported
payload is marked reviewed, tested, accepted, validated, or executable.

## Import Flow

1. The CLI receives a local PATT snapshot directory/archive or explicitly
   fetches one configured PATT slice.
2. Every source file is stored in `SnapshotStore` before parsing.  Its
   SHA-256 digest, source URL, commit/revision and retrieval time are retained.
3. The shared pure extractor parses Markdown and optional Intruder wordlists.
   It preserves whole multi-line CSRF/upload payloads, drops commentary and
   console output, and applies the configured per-family cap.
4. The v2 materializer creates or updates document, evidence, family and
   technology context through `GraphRepository`, and writes exact candidates
   to the `PATTIndex` sidecar.
5. The command returns per-slice counts, skipped-over-cap counts, headings with
   no payloads, snapshot digests and diagnostics.

An empty or malformed source is a reported import failure.  A heading alone
does not create a `PayloadFamily -> Technology` applicability edge; at least
one source-backed payload is required.

## Query and UI Contract

The v2 API exposes payload references in two read-only forms:

- `GET /cwes/{cwe_id}/payloads` returns payload families and payload references
  for one canonical CWE;
- the existing CVE case-file response may expose matching payload references
  only through its reified weakness assertions, preserving the assertion status
  and source evidence that made the CWE applicable.

Results include `origin`, `curation_status`, `validation_status`, source
locator, snapshot digest, family, technology, pagination and truncation
metadata. API
responses must label untested PATT values as reference material.

The v2 UI adds a `PATT reference payloads` panel.  It must display the source,
family, technology, locator and untested status.  It must not call them
validated payloads, executable commands, exploit results, or automatic attack
steps.

## Scenario and Trust Invariants

PATT import does not change the current semantic-scenario contract:

- no endpoint, parameter, payload binding or callback is supplied to a target;
- PATT presence does not make a scenario `testReady` or `validated`;
- only the existing payload-proposal plus validation-record plus accepted-oracle
  workflow can make locally reviewed material test-ready;
- a `SIMILAR_TO` relation remains a reference and cannot transfer raw payload
  validation across weaknesses;
- temporal reads exclude PATT nodes and edges without valid source timestamps
  or snapshot provenance.

## Tests and Verification

The implementation requires tests for:

- extraction of one-line, multi-line and Intruder payloads;
- comment/transcript/table-output rejection;
- per-family cap and diagnostics;
- stable idempotent import and SHA-256 provenance;
- no direct CVE/GHSA-to-payload relation;
- no automatic `validated` or `testReady` state;
- CWE and assertion-scoped CVE payload read contracts;
- UI labels for reference/untested material;
- in-memory and opt-in Neo4j parity for the payload graph;
- preservation of existing PATT methodology importer behavior.

Focused tests run before the full suite.  Full verification includes
`.venv/bin/python -m pytest -q`, the catalog/migration verifiers, and
`git diff --check`.  A v2 Neo4j payload parity check is separately run when the
test service and `NEO4J_V2_TEST_URI` are available.

## Acceptance Criteria

The feature is accepted when the ten curated slices can be imported explicitly
into a canonical v2 repository, raw payloads retain immutable source evidence,
the API/UI expose them as untested references, the graph cannot represent them
as direct CVE facts or validated execution, and all focused plus full tests
pass in an environment with the required loopback/Neo4j permissions.
