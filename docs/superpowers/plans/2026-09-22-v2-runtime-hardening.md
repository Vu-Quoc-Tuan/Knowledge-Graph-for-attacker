# V2 Runtime Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden the canonical v2 UI/API and make technology-to-CVE search bounded, ranked, provenance-aware, and parity-tested while leaving credential handling, default password, and API authentication unchanged.

**Architecture:** Keep the dependency-light HTTP server and `GraphRepository` contract. Put shared search normalization/scoring in `src/ckg/graph/search.py`, make both memory and Neo4j adapters consume the same result contract, and keep UI state handling in the packaged `src/ckg/ui/v2` assets.

**Tech Stack:** Python 3.12, standard-library `http.server`, Neo4j driver, dataclasses/Pydantic models already present, vanilla JavaScript UI, pytest.

## Global Constraints

- Do not modify credential loading, `change-me-please` defaults, or authentication/authorization behavior.
- Do not remove explicit legacy migration adapters.
- Preserve existing v2 API paths; new query metadata must be additive.
- Use `apply_patch` for source edits and run focused tests after every task.
- Do not commit changes.

---

### Task 1: Remove the misleading Cypher UI and expose backend-aware/partial status

**Files:**
- Modify: `src/ckg/ui/v2/index.html:109-134`
- Modify: `src/ckg/ui/v2/app.js:198-203, 428-436, 438-472`
- Modify: `src/ckg/api/main.py:379-391`
- Test: `tests/integration/test_v2_ui_browser.py`

**Interfaces:**
- Consumes: `/healthz`, `/cves/{id}`, `/cves/{id}/historical-neighbors`, `/cves/{id}/scenarios`, `/cves/{id}/subgraph`.
- Produces: a UI that does not render or copy raw Cypher and reports backend plus partial resource failures.

- [x] **Step 1: Write failing browser assertions**

  Extend the browser smoke fixture so the DOM dump must not contain `Cypher Query`, `btn-copy-cypher`, or `Neo4j đã đồng bộ` when the repository is in-memory. Add a test fixture route failure and assert a visible partial-load marker.

- [x] **Step 2: Run the focused browser test**

  Run: `.venv/bin/python -m pytest tests/integration/test_v2_ui_browser.py -q`

  Expected: FAIL because the existing UI contains the Cypher terminal and hardcoded Neo4j notice.

- [x] **Step 3: Remove the Cypher markup and JavaScript**

  Delete the `cypher-terminal` block from `index.html`, delete `updateCypherDisplay`, delete the copy listener, and remove its calls from `renderCase`/empty-state code. Keep graph visualization and case navigation unchanged.

- [x] **Step 4: Add backend and partial status rendering**

  Fetch `/healthz` once during initialization and store `backend`/`graphSchema`. Change `openCase` to await all four requests, render successful sections, collect failed section names, and set the notice to a warning containing the backend and failed sections. Do not make an auxiliary section failure turn a valid case-file response into a blank case.

- [x] **Step 5: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/integration/test_v2_ui_browser.py tests/integration/test_v2_api.py -q`

  Expected: PASS.

### Task 2: Bound HTTP bodies and stabilize internal error responses

**Files:**
- Modify: `src/ckg/api/main.py:362-377, 476-510`
- Modify: `src/ckg/config/settings.py:14-25, 70-105`
- Modify: `src/ckg/__main__.py:70-90`
- Test: `tests/integration/test_v2_api.py`

**Interfaces:**
- Consumes: existing JSON POST endpoints.
- Produces: `413` for bodies over the configured limit and stable `{"error":"internal server error"}` responses for unexpected exceptions.

- [x] **Step 1: Add failing API tests**

  Add a test that POSTs a body larger than the configured limit and expects `413`. Add a handler test whose repository raises `RuntimeError("secret internal detail")` and assert the response is `500` with exactly `{"error": "internal server error"}` and without the detail.

- [x] **Step 2: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/integration/test_v2_api.py -q`

  Expected: FAIL because the handler currently reads the declared body without a size limit and returns `str(exc)`.

- [x] **Step 3: Implement the body limit and stable errors**

  Add a non-secret `max_request_body_bytes` setting defaulting to `2 * 1024 * 1024`, pass it to `make_handler`, reject invalid/oversized `Content-Length` before reading, and use the stable internal error body. Preserve current `400` validation messages and all authentication behavior (none is added in this task).

- [x] **Step 4: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/integration/test_v2_api.py -q`

  Expected: PASS.

### Task 3: Preserve CPE identity and add shared product normalization/scoring

**Files:**
- Modify: `src/ckg/ingestion/cve/models.py:21-29`
- Modify: `src/ckg/ingestion/cve/parser.py:100-135, 197-214`
- Modify: `src/ckg/ingestion/cve/importer.py:100-210`
- Modify: `src/ckg/graph/models.py:1-90`
- Modify: `src/ckg/graph/search.py:1-165`
- Test: `tests/unit/test_cve_technology_search.py`
- Test: `tests/unit/test_structured_vulnerability_ingestion.py`

**Interfaces:**
- Consumes: NVD CPE criteria and CVE Services affected product records.
- Produces: Product properties containing stable normalized fields, `cpe_uri` when available, aliases, and deterministic match metadata.

- [x] **Step 1: Write failing normalization/scoring tests**

  Add fixtures for `grafana`, `grafana-enterprise`, `grafana/grafana`, and an escaped CPE criterion. Assert the original criterion is retained, aliases match case/word variants, unrelated ecosystem-only matches do not match, and result ordering prefers exact product matches over vendor substring matches.

- [x] **Step 2: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/unit/test_cve_technology_search.py tests/unit/test_structured_vulnerability_ingestion.py -q`

  Expected: FAIL because the current DTO/importer does not preserve the CPE criterion and search only performs raw substring matching.

- [x] **Step 3: Implement the data fields**

  Add optional `cpe_uri` and `aliases` fields to `AffectedProduct`, set `cpe_uri` from the original NVD `criteria`, derive aliases from vendor/product/package without dropping the original values, and persist them on `Product` nodes. Keep old serialized records readable by using empty defaults.

- [x] **Step 4: Implement shared normalization and score**

  In `graph/search.py`, normalize Unicode/case/whitespace/separators, match only product identity fields (`name`, `package_name`, `vendor`, `cpe_uri`, `aliases`), assign exact-name > alias/word-prefix > vendor > substring scores, and return a match reason. Keep source-state suppression and CVE/GHSA folding after candidate generation.

- [x] **Step 5: Align Neo4j candidate filtering**

  Update `Neo4jGraphRepository.search_vulnerabilities` to query the same identity fields and pass the candidate rows through the shared scorer/folder. Keep the bounded candidate limit and deterministic final ordering.

- [x] **Step 6: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/unit/test_cve_technology_search.py tests/unit/test_structured_vulnerability_ingestion.py tests/graph/test_v2_neo4j.py -q`

  Expected: memory tests pass; Neo4j tests either pass with `NEO4J_V2_TEST_URI` or report the existing explicit opt-in skip.

### Task 4: Add pagination and explicit truncation/source metadata

**Files:**
- Modify: `src/ckg/graph/ports.py:55-78`
- Modify: `src/ckg/api/main.py:175-208, 443-468, 210-247`
- Modify: `src/ckg/ingestion/cve/nvd_client.py:35-97`
- Modify: `src/ckg/ui/v2/app.js:484-510, 513-545`
- Test: `tests/unit/test_cve_technology_search.py`
- Test: `tests/integration/test_v2_api.py`

**Interfaces:**
- Consumes: existing `technology`, `from_year`, `to_year`, `limit` query parameters.
- Produces: additive response fields `total`, `offset`, `limit`, `returned`, `truncated`, and per-result `match_reason`/`relevance`.

- [x] **Step 1: Write failing pagination/truncation tests**

  Assert `GET /cves?technology=Grafana&limit=1&offset=1` returns the second stable result and metadata. Mock an NVD result with more records than `max_records` and assert the ingest response exposes `truncated: true`.

- [x] **Step 2: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/unit/test_cve_technology_search.py tests/integration/test_v2_api.py -q`

  Expected: FAIL because the current endpoint has no offset/total/truncation contract.

- [x] **Step 3: Implement additive pagination**

  Validate `offset >= 0`, retain `1 <= limit <= 500`, compute the full bounded candidate list once, return the requested slice, and include metadata. Keep the default response shape (`cves` and `query`) unchanged for existing callers.

- [x] **Step 4: Mark bounded NVD refreshes**

  Track whether the aggregate fetch stopped because `max_records` was reached while upstream reported additional results. Persist the flag in the ingestion job/result metadata and return it from `POST /ingest/cves/search`.

- [x] **Step 5: Update UI results**

  Render the returned count and a truncation notice. Keep the result buttons navigating to the existing case-file flow.

- [x] **Step 6: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/unit/test_cve_technology_search.py tests/integration/test_v2_api.py tests/integration/test_v2_ui_browser.py -q`

  Expected: PASS.

### Task 5: Make catalog/migration completeness diagnostics explicit

**Files:**
- Modify: `scripts/verify_canonical_catalogs.py`
- Modify: `scripts/verify_legacy_v2_migration.py`
- Modify: `src/ckg/migration/legacy_registry.py`
- Modify: `src/ckg/migration/legacy_vulnerability_events.py`
- Test: `tests/unit/test_legacy_registry_migration.py`
- Test: `tests/unit/test_legacy_vulnerability_event_migration.py`

**Interfaces:**
- Consumes: existing canonical snapshots and legacy registries.
- Produces: structured diagnostic counts/reasons; unresolved or unverifiable records remain excluded from promoted reasoning facts.

- [x] **Step 1: Write failing diagnostic tests**

  Add a fixture with one unresolved view membership and one missing snapshot evidence artifact. Assert the verifier reports a reasoned diagnostic and the migration report marks the evidence unverifiable instead of counting it as valid.

- [x] **Step 2: Run focused tests**

  Run: `.venv/bin/python -m pytest tests/unit/test_legacy_registry_migration.py tests/unit/test_legacy_vulnerability_event_migration.py -q`

  Expected: FAIL because current output only exposes aggregate unresolved IDs/missing IDs.

- [x] **Step 3: Implement explicit diagnostic fields**

  Add stable `diagnostic_code`/`diagnostic_reason` values for unresolved catalog references and missing evidence artifacts. Preserve existing report fields for compatibility and keep fail-closed promotion behavior.

- [x] **Step 4: Run focused tests and verifiers**

  Run: `.venv/bin/python -m pytest tests/unit/test_legacy_registry_migration.py tests/unit/test_legacy_vulnerability_event_migration.py -q && .venv/bin/python -m scripts.verify_canonical_catalogs && .venv/bin/python -m scripts.verify_legacy_v2_migration`

  Expected: PASS; unresolved diagnostics remain visible rather than silently disappearing.

### Task 6: Full verification and live Neo4j checkpoint

**Files:**
- Modify: `README.md:51-64, 239-258`
- Modify: `tests/integration/test_v2_ui_browser.py` only if final browser assertions need fixture updates.

**Interfaces:**
- Consumes: all prior changes.
- Produces: documented reproducibility commands and a verified final worktree state.

- [x] **Step 1: Run static/source checks**

  Run: `git diff --check && .venv/bin/python -m py_compile $(rg --files -g '*.py')`

  Expected: exit 0.

- [x] **Step 2: Run the full suite outside restricted socket sandbox**

  Run: `.venv/bin/python -m pytest -q -rs`

  Expected: all runnable tests pass; only explicit environment-dependent Neo4j skips remain.

- [x] **Step 3: Run build and catalog checks**

  Run: `.venv/bin/python -m ckg build --dry-run && .venv/bin/python -m scripts.verify_canonical_catalogs && .venv/bin/python -m scripts.verify_legacy_v2_migration`

  Expected: all commands exit 0 and report graph/catalog/migration counts.

- [x] **Step 4: Run live Neo4j parity when the test service is available**

  Run: `docker compose --profile test up -d --wait neo4j-test && NEO4J_V2_TEST_URI=bolt://localhost:7688 NEO4J_V2_TEST_USER=neo4j NEO4J_V2_TEST_PASSWORD=test-password .venv/bin/python -m pytest tests/graph/test_v2_neo4j.py -q`

  Expected: v2 Neo4j parity tests pass. If the service is unavailable, report the exact skip and do not claim live parity.

- [x] **Step 5: Re-scan excluded scope**

  Run: `rg -n "change-me-please|NEO4J_PASSWORD|Authorization|Bearer|/auth|login" src/ckg docker-compose.yaml`

  Expected: no changes were made to the excluded credential/default-password/auth areas; report them separately in the handoff.
