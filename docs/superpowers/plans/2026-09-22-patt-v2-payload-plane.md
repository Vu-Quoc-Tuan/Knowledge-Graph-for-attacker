# PATT V2 Payload Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Import the ten curated PayloadsAllTheThings slices into the canonical v2 graph as immutable, source-backed, untested payload references queryable by CWE/CVE and visible in the v2 UI.

**Architecture:** A pure parser in `src/ckg/ingestion/patt` extracts structured payload candidates. A snapshot-first v2 importer materializes them through `GraphRepository`. The old `GraphSink` loader becomes a compatibility consumer of the shared parser. API/UI expose reference material only; they never claim execution or validation.

**Tech Stack:** Python 3.12, Pydantic v2, PyYAML, GraphRepository (in-memory and Neo4j), standard-library HTTP server, vanilla HTML/JS/CSS, pytest.

> **Current implementation amendment:** the original plan below described a
> granular graph with one `Payload` and `PATTSection` node per extracted
> candidate. The implemented canonical v2 plane is intentionally compact:
> graph nodes stop at `PayloadFamily`/`Technology`. `PATTDocument`/PATT
> evidence metadata and their relationships are retained losslessly in the
> snapshot-backed `compact_details.sqlite3` sidecar; exact candidates are
> stored in `patt_payloads.sqlite3` and exposed through paginated API reads.
> The historical task text is retained as provenance for the implementation,
> but this amendment governs the current runtime contract.

## Global Constraints

- Cover exactly CWE-89, CWE-79, CWE-78, CWE-918, CWE-22, CWE-434, CWE-352, CWE-94, CWE-502, and CWE-93, including the supported Burp Intruder wordlists for slices that declare an `intruder_family`.
- `ckg build`, GET endpoints, and UI reads never fetch PATT from the network.
- Snapshot every source file before parsing and retain URL, immutable revision, SHA-256, file name, and section locator.
- Imported payloads are always `origin="patt"`, `curation_status="upstream_curated"`, and `validation_status="untested"`.
- Never create direct CVE/GHSA-to-payload edges, validated payloads, `testReady` scenarios, or target execution bindings.
- Retain existing methodology-only PATT importer behavior: fenced code blocks do not automatically become payload nodes there.
- Preserve unrelated dirty-worktree changes and do not modify credentials, default passwords, authentication, or network binding.

---

### Task 1: Share the existing PATT extraction rules with v2

**Files:**

- Create: `src/ckg/ingestion/patt/slices.py`
- Create: `src/ckg/ingestion/patt/payload_extractor.py`
- Modify: `ingest/slices.py`
- Modify: `ingest/patt_loader.py`
- Test: `tests/unit/test_patt_payload_extractor.py`

**Interfaces:**

- Produces `PayloadCandidate` and `PayloadExtractionReport` from a `VulnSlice` and one Markdown file, plus a pure wordlist extractor for supported Burp Intruder `.txt` files.
- Preserves the public `ingest.patt_loader.load_patt()` signature and its existing report keys.

- [ ] **Step 1: Write failing parser tests**

```python
from ckg.ingestion.patt.payload_extractor import extract_payload_candidates
from ckg.ingestion.patt.slices import SLICES


def test_extracts_xss_and_rejects_console_output() -> None:
    slice_ = next(item for item in SLICES if item.weakness_id == "CWE-79")
    report = extract_payload_candidates(
        slice_,
        source_file="README.md",
        source_url="https://example.test/xss",
        markdown="## XSS\n```html\n<img src=x onerror=alert(1)>\nHTTP/1.1 500\n```",
    )
    assert [candidate.value for candidate in report.candidates] == [
        "<img src=x onerror=alert(1)>"
    ]


def test_keeps_csrf_form_as_one_multiline_payload() -> None:
    slice_ = next(item for item in SLICES if item.weakness_id == "CWE-352")
    report = extract_payload_candidates(
        slice_,
        source_file="README.md",
        source_url="https://example.test/csrf",
        markdown="## CSRF\n```html\n<form action='/transfer'>\n<input name='amount' value='1'>\n</form>\n```",
    )
    assert len(report.candidates) == 1
    assert "<form" in report.candidates[0].value
    assert "</form>" in report.candidates[0].value
```

- [ ] **Step 2: Confirm the test is red**

Run:

```bash
.venv/bin/python -m pytest tests/unit/test_patt_payload_extractor.py -q
```

Expected: collection fails because `payload_extractor` does not exist.

- [ ] **Step 3: Move the slice catalog into canonical v2**

Copy `FamilySpec`, `VulnSlice`, and all ten existing `SLICES` values from `ingest/slices.py` into `src/ckg/ingestion/patt/slices.py` unchanged. Replace root `ingest/slices.py` with this compatibility module:

```python
"""Compatibility re-export for the canonical PATT slice catalog."""

from ckg.ingestion.patt.slices import FamilySpec, SLICES, VulnSlice

__all__ = ["FamilySpec", "SLICES", "VulnSlice"]
```

- [ ] **Step 4: Create the pure payload extraction API**

Move the pure Markdown logic from `ingest/patt_loader.py` into `src/ckg/ingestion/patt/payload_extractor.py`: comment filtering, transcript filtering, result-table filtering, structural-fragment filtering, fenced-block splitting, table-cell extraction, heading-family selection, payload marker checks, multi-line policy, and per-family cap.

```python
@dataclass(frozen=True)
class PayloadCandidate:
    value: str
    family_key: str
    family_name: str
    technology: str | None
    section_heading: str
    locator: str
    extraction: str


@dataclass(frozen=True)
class PayloadExtractionReport:
    candidates: tuple[PayloadCandidate, ...]
    heading_families: tuple[str, ...]
    skipped_over_cap: int
    unclassified_table_spans: int
    headings_without_payloads: tuple[str, ...]


def extract_payload_candidates(
    slice_: VulnSlice,
    *,
    source_file: str,
    source_url: str,
    markdown: str,
    technology: str | None = None,
    max_payloads_per_family: int = 400,
) -> PayloadExtractionReport:
    return PayloadExtractionReport(
        candidates=(),
        heading_families=(),
        skipped_over_cap=0,
        unclassified_table_spans=0,
        headings_without_payloads=(),
    )
```

Use `/sections/{section.index}` as the candidate locator. The pure module must not import `db.sink`, `schema.models`, an HTTP client, or a graph repository.

- [ ] **Step 5: Make the legacy loader consume the shared extractor**

Keep network fetch, GraphSink writes, and legacy report assembly in `ingest/patt_loader.py`. Replace its local candidate loop with the shared extraction API; materialize its existing legacy `Payload` nodes from returned candidates. Preserve return keys `cwe`, `families`, `payloads`, `intruder_payloads`, `techs`, `skipped_over_cap`, `unclassified_table_spans`, `headings_without_payloads`, `over_cap`, and `unevidenced`.

- [ ] **Step 6: Verify parser and compatibility behavior**

Run:

```bash
.venv/bin/python -m pytest tests/unit/test_patt_payload_extractor.py tests/test_authoritative_readiness.py tests/test_local_scenario_gate.py -q
```

Expected: all pass; the existing slice readiness and local scenario behavior remain unchanged.

### Task 2: Materialize PATT payloads in the canonical graph

**Files:**

- Create: `src/ckg/ingestion/patt/payload_importer.py`
- Create: `src/ckg/application/ingest_patt.py`
- Modify: `src/ckg/ingestion/patt/__init__.py`
- Test: `tests/unit/test_patt_payload_importer.py`

**Interfaces:**

- Consumes `GraphRepository`, one selected PATT slice, snapshot-backed source documents, retrieval time, and a cap.
- Produces `PATTStructuredImportReport`.
- Writes only v2 `GraphNode` and `GraphEdge` entities atomically and idempotently.

- [ ] **Step 1: Write failing source-provenance tests**

```python
def test_import_keeps_patt_provenance_and_untested_state(tmp_path) -> None:
    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[GraphNode(label="CWE", node_id="CWE-79", props={})], edges=[])
    report = ingest_patt_sources(
        repository,
        slice_cwe_id="CWE-79",
        sources=(PATTSourceFile("README.md", "https://example.test/xss", "a" * 40, "## XSS\n```\n<x>\n```"),),
        retrieved_at=datetime(2026, 9, 22, tzinfo=timezone.utc),
        snapshot_root=tmp_path / "snapshots",
    )
    payload = repository.nodes("Payload")[0]
    assert report.payload_count == 1
    assert payload.props["origin"] == "patt"
    assert payload.props["curation_status"] == "upstream_curated"
    assert payload.props["validation_status"] == "untested"
    assert payload.props["source_snapshot_digest"].startswith("sha256:")
    assert repository.edges("HAS_PAYLOAD_FAMILY")[0].subject_id == "CWE-79"
    assert not [edge for edge in repository.edges() if edge.subject_id.startswith("CVE-")]
```

- [ ] **Step 2: Confirm the importer test is red**

Run:

```bash
.venv/bin/python -m pytest tests/unit/test_patt_payload_importer.py -q
```

Expected: import failure for missing `ckg.application.ingest_patt`.

- [ ] **Step 3: Add typed source/report records**

Create `payload_importer.py` with:

```python
@dataclass(frozen=True)
class PATTSourceFile:
    source_file: str
    source_url: str
    source_revision: str
    content: str
    kind: Literal["markdown", "wordlist"] = "markdown"
    technology: str | None = None


@dataclass(frozen=True)
class PATTStructuredImportReport:
    slice_cwe_id: str
    document_count: int
    payload_count: int
    family_count: int
    technology_count: int
    skipped_over_cap: int
    unclassified_table_spans: int
    headings_without_payloads: tuple[str, ...]
    snapshot_digests: tuple[str, ...]
```

Use SHA-256 of stable inputs for all node/edge IDs. Include the source snapshot digest in document, section, evidence, and payload identities so a changed upstream source becomes a distinct revision.

- [ ] **Step 4: Implement v2 graph materialization**

For each source file, call:

```python
snapshot_digest = SnapshotStore(snapshot_root).put(source.content.encode("utf-8"))
```

Create `PATTDocument`, `Evidence`, `PayloadFamily`, and optional `Technology`
nodes. Write exact candidate rows to `PATTIndex`; do not create `Payload` or
raw-payload `PATTSection` nodes. Create only these graph edges:

```python
GraphEdge(edge_id=family_edge_id, edge_type="HAS_PAYLOAD_FAMILY", subject_id=cwe_id, object_id=family_id)
GraphEdge(edge_id=family_source_edge_id, edge_type="SOURCED_FROM", subject_id=family_id, object_id=document_id)
GraphEdge(edge_id=document_evidence_edge_id, edge_type="SUPPORTED_BY", subject_id=document_id, object_id=evidence_id)
GraphEdge(edge_id=family_technology_edge_id, edge_type="APPLIES_TO", subject_id=family_id, object_id=technology_id)
```

Create `APPLIES_TO` only when a candidate exists for that family/technology. Reject an absent CWE or an unknown slice. Never create CVE/GHSA payload edges or `Scenario` nodes.

- [ ] **Step 5: Add snapshot-first application use case**

Create `src/ckg/application/ingest_patt.py`:

```python
def ingest_patt_sources(
    repository: GraphRepository,
    *,
    slice_cwe_id: str,
    sources: tuple[PATTSourceFile, ...],
    retrieved_at: datetime,
    snapshot_root: str | Path,
    max_payloads_per_family: int = 400,
) -> PATTStructuredImportReport:
    return PATTStructuredImportReport(
        slice_cwe_id=slice_cwe_id,
        document_count=0,
        payload_count=0,
        family_count=0,
        technology_count=0,
        skipped_over_cap=0,
        unclassified_table_spans=0,
        headings_without_payloads=(),
        snapshot_digests=(),
    )
```

Sort sources by `source_file`, validate non-empty source/revision values, snapshot all raw bytes before parse, and call the materializer once with the complete batch.

- [ ] **Step 6: Add cap, idempotence, and trust regression tests**

```python
ingest_patt_sources(repository, slice_cwe_id="CWE-79", sources=sources, retrieved_at=retrieved_at, snapshot_root=snapshot_root)
ingest_patt_sources(repository, slice_cwe_id="CWE-79", sources=sources, retrieved_at=retrieved_at, snapshot_root=snapshot_root)
assert len(repository.nodes("Payload")) == expected_payload_count
assert all(node.props["validation_status"] == "untested" for node in repository.nodes("Payload"))
assert repository.nodes("Scenario") == []
```

Use `max_payloads_per_family=1` with two XSS candidates and assert one retained payload plus `skipped_over_cap == 1`.

- [ ] **Step 7: Verify v2 PATT import behavior**

Run:

```bash
.venv/bin/python -m pytest tests/unit/test_patt_payload_importer.py tests/unit/test_technique_planes.py -q
```

Expected: all pass; direct methodology import still creates no raw `Payload` node.

### Task 3: Add explicit local-manifest PATT ingestion to the CLI

**Files:**

- Modify: `src/ckg/__main__.py`
- Modify: `scripts/bootstrap_patt.py`
- Test: `tests/integration/test_patt_cli.py`

**Interfaces:**

- Consumes `ckg ingest --patt-cwe CWE-79 --file patt-xss-manifest.json --memory`.
- Produces JSON `PATTStructuredImportReport`.
- Keeps `ckg build` free of PATT fetch/import side effects.

- [ ] **Step 1: Write a failing local-manifest CLI test**

```python
def test_ckg_ingest_patt_from_local_manifest(tmp_path, capsys) -> None:
    source = tmp_path / "patt.json"
    source.write_text(
        json.dumps({"sources": [{
            "source_file": "README.md",
            "source_url": "https://example.test/xss",
            "source_revision": "a" * 40,
            "content": "## XSS\n```\n<x>\n```",
            "kind": "markdown",
        }]}),
        encoding="utf-8",
    )
    assert main(["ingest", "--patt-cwe", "CWE-79", "--file", str(source), "--memory"]) == 0
    assert json.loads(capsys.readouterr().out)["payload_count"] == 1
```

- [ ] **Step 2: Confirm the CLI test is red**

Run:

```bash
.venv/bin/python -m pytest tests/integration/test_patt_cli.py -q
```

Expected: argparse rejects `--patt-cwe`.

- [ ] **Step 3: Extend `ckg ingest` with explicit PATT flags**

Add beside existing ingest flags:

```python
ingest.add_argument("--patt-cwe", help="Import one curated PATT payload slice for this CWE")
ingest.add_argument("--source-revision", help="Immutable PATT source revision")
ingest.add_argument("--max-payloads-per-family", type=int)
```

In `_ingest`, make `--patt-cwe` mutually exclusive with `--cve` and `--cwe`, require `--file`, parse UTF-8 JSON, and require a non-empty `sources` list. Each source requires `source_file`, `source_url`, `source_revision`, and `content`; optional `kind` is `markdown` or `wordlist` and optional `technology` scopes the source. Construct `PATTSourceFile` records, call `ingest_patt_sources` with the selected CWE, and print `asdict(report)`. A `wordlist` source is valid only for a slice with `intruder_family`.

- [ ] **Step 4: Rework bootstrap helper to emit a v2 import manifest**

In `scripts/bootstrap_patt.py`, retain fetch only as an explicit action. Require an immutable 40+ hex commit when fetching a remote PATT source; reject branch names such as `master`. Emit this manifest to stdout or an explicit `--output` path:

```json
{
  "sources": [
    {
      "source_file": "README.md",
          "source_url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/0123456789abcdef0123456789abcdef01234567/XSS%20Injection/README.md",
          "source_revision": "0123456789abcdef0123456789abcdef01234567",
          "content": "## XSS\n```html\n<img src=x onerror=alert(1)>\n```",
          "kind": "markdown"
    }
  ]
}
```

Remove its current temporary `InMemoryGraphRepository` import path so it does not imply graph persistence.

- [ ] **Step 5: Verify explicit import boundaries**

Run:

```bash
.venv/bin/python -m pytest tests/integration/test_patt_cli.py tests/unit/test_patt_payload_importer.py -q
```

Expected: local manifest import succeeds; unknown/mixed ingest modes fail clearly; branch source revision is rejected; no build command test observes a PATT network call.

### Task 4: Expose PATT reference payloads through v2 API

**Files:**

- Modify: `src/ckg/api/main.py`
- Test: `tests/unit/test_patt_payload_api.py`
- Test: `tests/integration/test_v2_api.py`
- Test: `tests/graph/test_v2_neo4j.py`

**Interfaces:**

- Produces `CKGApplication.cwe_payloads(identifier, limit=100)`.
- Produces `CKGApplication.vulnerability_payloads(identifier, limit=100)`.
- Routes `GET /cwes/{id}/payloads` and `GET /cves/{id}/payloads`.

- [ ] **Step 1: Write failing application/API tests**

```python
def test_cwe_payload_api_returns_only_untested_patt_references() -> None:
    app = CKGApplication(repository_with_patt_payload(), snapshot_root="snapshots")
    result = app.cwe_payloads("CWE-79")
    assert result["cwe_id"] == "CWE-79"
    assert result["payloads"][0]["props"]["origin"] == "patt"
    assert result["payloads"][0]["props"]["validation_status"] == "untested"
    assert result["reference_status"] == "upstream_curated_untested"


def test_cve_payload_api_uses_only_reified_weakness_assertions() -> None:
    result = app.vulnerability_payloads("CVE-2026-10001")
    assert result["asserted_cwe_ids"] == ["CWE-79"]
    assert all(item["cwe_id"] == "CWE-79" for item in result["payloads"])
```

- [ ] **Step 2: Confirm the API tests are red**

Run:

```bash
.venv/bin/python -m pytest tests/unit/test_patt_payload_api.py tests/integration/test_v2_api.py -q
```

Expected: `AttributeError` for missing application methods and HTTP 404 for the routes.

- [ ] **Step 3: Implement safe payload traversal in `CKGApplication`**

Add a private helper:

```python
def _payload_references_for_cwes(
    self,
    cwe_ids: frozenset[str],
    *,
    limit: int,
) -> list[dict]:
    return []
```

Traverse `CWE --HAS_PAYLOAD_FAMILY--> PayloadFamily` and use the
`PATTIndex` sidecar for exact candidate rows. Resolve document/evidence context
through `SOURCED_FROM` and `SUPPORTED_BY`. Skip malformed rows unless the
fixed trust properties are `patt`, `upstream_curated`, and `untested`.

- [ ] **Step 4: Add application methods and route dispatch**

```python
def cwe_payloads(self, identifier: str, *, limit: int = 100) -> dict:
    return {"cwe_id": identifier, "payloads": [], "returned": 0, "limit": limit, "truncated": False, "reference_status": "upstream_curated_untested"}

def vulnerability_payloads(self, identifier: str, *, limit: int = 100) -> dict:
    return {"vulnerability_id": identifier, "asserted_cwe_ids": [], "payloads": [], "returned": 0, "limit": limit, "truncated": False, "reference_status": "upstream_curated_untested"}
```

`vulnerability_payloads` derives CWE IDs only through:

```text
CVE/GHSA -> HAS_WEAKNESS_ASSERTION -> WeaknessAssertion -> MAPS_TO -> CWE
```

Return `returned`, `limit`, `truncated`, `reference_status`, and either `cwe_id` or `vulnerability_id`; CVE output also includes sorted `asserted_cwe_ids`. Parse a positive `limit`, cap it at 500, and register both new route cases before generic scenario routes.

- [ ] **Step 5: Verify HTTP behavior with loopback permission**

Run:

```bash
.venv/bin/python -m pytest tests/unit/test_patt_payload_api.py tests/integration/test_v2_api.py -q
```

Expected: all pass. If the sandbox denies socket bind, rerun the same command in a permitted environment and report that separately.

- [ ] **Step 6: Add v2 Neo4j round-trip parity coverage**

Add a `tests/graph/test_v2_neo4j.py` test that writes one CWE,
`PayloadFamily`, `PATTDocument`, and `Evidence`, then verifies the compact
labels/edge IDs after a Neo4j round-trip. Verify exact payload provenance and
pagination separately through `PATTIndex`.

Run:

```bash
NEO4J_V2_TEST_URI=bolt://localhost:7688 NEO4J_V2_TEST_USER=neo4j NEO4J_V2_TEST_PASSWORD=test-password .venv/bin/python -m pytest tests/graph/test_v2_neo4j.py -q
```

Expected: the new payload parity test passes whenever the opt-in test service is available.

### Task 5: Render reference-only PATT payloads in v2 UI

**Files:**

- Modify: `src/ckg/ui/v2/index.html`
- Modify: `src/ckg/ui/v2/app.js`
- Modify: `src/ckg/ui/v2/styles.css`
- Test: `tests/integration/test_v2_ui_browser.py`
- Test: `tests/unit/test_ui_asset_source.py`

**Interfaces:**

- Consumes `GET /cves/{id}/payloads?limit=50`.
- Produces a `PATT reference payloads` panel with family, technology, source locator, digest and untested status.
- A payload endpoint failure is partial loading; it cannot hide the case file or other panels.

- [ ] **Step 1: Write browser assertions before markup exists**

Extend `test_v2_case_file_ui_renders_a_loaded_case_in_chrome` with a temporary
PATT sidecar row and assert:

```python
assert "PATT reference payloads" in result.stdout
assert "Upstream curated - untested" in result.stdout
assert "Synthetic PATT payload" in result.stdout
```

Add a partial application fixture that raises from `vulnerability_payloads` and assert:

```python
assert "Partial load: payload references" in result.stdout
```

- [ ] **Step 2: Confirm the browser tests are red**

Run:

```bash
.venv/bin/python -m pytest tests/integration/test_v2_ui_browser.py -q
```

Expected: missing panel text assertion fails.

- [ ] **Step 3: Add an accessible panel to the canonical UI**

```html
<section class="case-panel" id="payload-references-panel" aria-labelledby="payload-references-heading">
  <h2 id="payload-references-heading">PATT reference payloads</h2>
  <p class="panel-note">Upstream reference material. It has not been validated against this target.</p>
  <div id="payload-references-content" aria-live="polite"></div>
</section>
```

Do not add controls labelled Run, Exploit, Attack, Execute, or Validate.

- [ ] **Step 4: Fetch/render with escaped text only**

Add the endpoint to the case-load `Promise.allSettled` map:

```javascript
payloadReferences: `/cves/${encodeURIComponent(cveId)}/payloads?limit=50`,
```

Implement:

```javascript
function renderPayloadReferences(payload) {
  // Render family, technology, source file, locator, digest prefix and value.
  // The fixed visible status is "Upstream curated - untested".
}
```

Render raw payload value with `textContent` or the existing escaping helper, never raw `innerHTML` interpolation. On request failure, preserve all other panels and show `Partial load: payload references`.

- [ ] **Step 5: Add constrained payload-value styling**

```css
.payload-reference-value {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 14rem;
  overflow: auto;
}
```

- [ ] **Step 6: Verify asset and browser tests**

Run:

```bash
.venv/bin/python -m pytest tests/unit/test_ui_asset_source.py tests/integration/test_v2_ui_browser.py -q
```

Expected: canonical packaged assets remain the only source and the browser fixture displays reference-only wording.

### Task 6: Document the boundary and complete verification

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture/03-ingestion.md`
- Create: `tests/regression/test_patt_v2_trust_boundary.py`

**Interfaces:**

- Documents explicit local-manifest import and the two read endpoints.
- Produces regression evidence that PATT material cannot become a direct CVE fact or a validated/test-ready scenario.

- [ ] **Step 1: Write the trust-boundary regression test**

```python
def test_patt_import_is_reference_only_and_cannot_validate_a_cve() -> None:
    repository = repository_with_cwe_and_cve_assertion()
    ingest_patt_sources(repository, slice_cwe_id="CWE-79", sources=sources, retrieved_at=retrieved_at, snapshot_root=snapshot_root)
    assert all(node.props["validation_status"] == "untested" for node in repository.nodes("Payload"))
    assert not [
        edge for edge in repository.edges()
        if edge.edge_type == "TARGETS" and edge.object_id.startswith("CVE-")
    ]
    assert not any(node.props.get("testReady") is True for node in repository.nodes("Scenario"))
```

- [ ] **Step 2: Confirm the regression is red before final trust checks**

Run:

```bash
.venv/bin/python -m pytest tests/regression/test_patt_v2_trust_boundary.py -q
```

Expected: failure until imported output is reference-only.

- [ ] **Step 3: Document explicit import and read contracts**

Add these commands to `README.md` and the ingestion architecture document:

```bash
.venv/bin/ckg ingest --patt-cwe CWE-79 --file patt-xss-manifest.json --memory
curl http://127.0.0.1:8088/cwes/CWE-79/payloads
curl http://127.0.0.1:8088/cves/CVE-2026-10001/payloads
```

State that build/read/UI never fetch PATT, PATT does not prove a target vulnerability, and proposal plus validation plus oracle workflow remains required for reviewed test material.

- [ ] **Step 4: Run focused verification**

```bash
.venv/bin/python -m pytest tests/unit/test_patt_payload_extractor.py tests/unit/test_patt_payload_importer.py tests/unit/test_patt_payload_api.py tests/unit/test_technique_planes.py tests/integration/test_patt_cli.py tests/integration/test_v2_api.py tests/integration/test_v2_ui_browser.py tests/regression/test_patt_v2_trust_boundary.py -q
```

Expected: all pass in a loopback-permitted environment.

- [ ] **Step 5: Run full repository verification**

Run the full pytest suite, then run `git --no-pager diff --check` and both catalog/migration verifiers. Report `PASS_WITH_DIAGNOSTICS` as non-promotion evidence.

```bash
.venv/bin/python -m pytest -q -rs
git --no-pager diff --check
.venv/bin/python -m scripts.verify_canonical_catalogs
.venv/bin/python -m scripts.verify_legacy_v2_migration
```

Expected: zero test failures, whitespace check exits zero, and verifier diagnostics remain visible.

- [ ] **Step 6: Run wheel and optional Neo4j verification**

```bash
make wheel-offline
NEO4J_V2_TEST_URI=bolt://localhost:7688 NEO4J_V2_TEST_USER=neo4j NEO4J_V2_TEST_PASSWORD=test-password .venv/bin/python -m pytest tests/graph/test_v2_neo4j.py -q
```

Expected: the wheel contains new `ckg/ingestion/patt` modules and canonical UI assets; payload parity passes when the test service is running.

## Plan Self-Review

- Spec coverage: Tasks 1-2 implement parser, snapshot provenance, graph materialization, cap, and idempotence. Task 3 creates explicit ingestion. Task 4 adds CWE/CVE API. Task 5 adds reference-only UI. Task 6 documents and verifies trust invariants.
- Placeholder scan: no unresolved implementation markers or unspecified test commands remain.
- Type consistency: `VulnSlice`, `PayloadCandidate`, `PATTSourceFile`, `PATTStructuredImportReport`, and `ingest_patt_sources` are introduced before their consumers.
