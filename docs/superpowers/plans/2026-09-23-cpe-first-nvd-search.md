# CPE-First NVD Technology Search Implementation Plan

> **For agentic workers:** Execute this plan task-by-task in the current checkout; preserve unrelated dirty-worktree changes.

**Goal:** Replace CKG's explicit NVD description-keyword refresh with CPE-resolved CVE retrieval while preserving local graph search and provenance.

**Architecture:** Resolve `technology` through NVD CPE API, group the returned CPE names into product families, then query NVD CVEs with the documented CPE filter. Allow an explicit `cpe_name` to bypass discovery, aggregate bounded results, and feed the existing snapshot/import path.

**Tech Stack:** Python >=3.12, `requests>=2.34.2`, existing CKG structured CVE importer and pytest.

## Global Constraints

- Do not modify the Combined DAST repository.
- Keep `GET /cves?technology=...` read-only and local to the imported graph.
- Do not fall back to CVE description `keywordSearch` when CPE discovery fails.
- Preserve NVD's maximum 120-day publication-date windows, bounded pagination, and configured `max_records`.
- Never persist the NVD API key in the graph, snapshot metadata, or returned payload.
- Mark any cap reached as truncated; do not claim complete results.

---

### Task 1: Implement NVD CPE discovery and CPE-scoped retrieval

**Files:**
- Modify: `src/ckg/ingestion/cve/nvd_client.py`
- Test: `tests/unit/test_nvd_client.py`

**Interfaces:**
- Consumes: `technology`, optional `cpe_name`, date bounds, API key, timeout, page size, and result cap.
- Produces: snapshot-ready aggregated NVD JSON plus metadata containing `truncated`, `upstream_total_known`, `search_mode`, queried CPE families, and CPE-candidate truncation.
- Client signature: `search_cves(technology: str | None, *, cpe_name: str | None = None, from_year: int, to_year: int, api_key: str | None = None, timeout: float = 30.0, results_per_page: int = 2000, max_records: int = 20_000, return_metadata: bool = False)`.
- Metadata keys: `truncated: bool`, `upstream_total_known: bool`, `search_mode: str`, `cpe_families: list[str]`, `cpe_candidates_truncated: bool`, and `cpe_candidate_count: int`.

- [ ] **Step 1: Add failing client tests.** Mock CPE results as `{"totalResults": 2, "products": [{"cpe": {"cpeName": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "deprecated": false}}]}`. Assert version-specific rows group to `cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*`; exact CPE mode calls only the CVE endpoint with `cpeName`; family mode calls it with `virtualMatchString`; results deduplicate by CVE ID; date windows are no longer than 120 days; pagination/caps set the right flags; and an empty CPE response yields `search_mode == "no_cpe_match"` and an empty valid NVD response.
- [ ] **Step 2: Run the client tests and confirm failure.**

  Run: `.venv/bin/python -m pytest tests/unit/test_nvd_client.py -q`

  Expected: FAIL because the client currently calls only the CVE API with `keywordSearch` and has no CPE resolution metadata.
- [ ] **Step 3: Add pure CPE normalization helpers** in `nvd_client.py`.

  ```python
  parts = _split_cpe23(cpe_name)
  if len(parts) != 13 or parts[:2] != ("cpe", "2.3"):
      return None
  if parts[2] not in {"a", "o", "h"} or parts[3] in {"", "*", "-"} or parts[4] in {"", "*", "-"}:
      return None
  family = ":".join((*parts[:5], *(["*"] * 8)))
  ```

  Ignore deprecated CPE names, group valid candidates by `(part, vendor, product)`, and sort the unique family strings before querying.
- [ ] **Step 4: Add sequential NVD CPE API lookup** at `https://services.nvd.nist.gov/rest/json/cpes/2.0`, using `keywordSearch`, `resultsPerPage`, and `startIndex`. Collect at most 50 unique product families; report when the cap truncates resolution.
- [ ] **Step 5: Replace the CVE description query** with `cpeName` for a validated exact CPE 2.3 input or `virtualMatchString` for each resolved family. For each query and each date window, send `resultsPerPage`, `startIndex`, `pubStartDate`, and `pubEndDate`; stop at `max_records`; deduplicate by CVE ID while keeping first-seen order; preserve the API-key header; call `raise_for_status()` on every response; and serialize `{"resultsPerPage": n, "startIndex": 0, "totalResults": n, "vulnerabilities": [...]}`.
- [ ] **Step 6: Run client tests.**

  Run: `.venv/bin/python -m pytest tests/unit/test_nvd_client.py -q`

  Expected: PASS, with all network calls mocked.

### Task 2: Connect CPE search metadata to the explicit ingest API

**Files:**
- Modify: `src/ckg/api/main.py`
- Test: `tests/unit/test_cve_technology_search.py`
- Test: `tests/integration/test_v2_api.py`

**Interfaces:**
- Consumes: `technology` or optional `cpe_name` in `POST /ingest/cves/search`.
- Produces: the existing ingestion report plus additive CPE-resolution metadata; unchanged local `GET /cves?technology=...` behavior.
- Successful response additions: `search_mode`, `cpe_families`, and `cpe_candidates_truncated`; no-match response has `status: "NO_CPE_MATCH"` and creates no graph or snapshot state.

- [ ] **Step 1: Add failing application/API tests** proving that a successful CPE-based fetch is ingested through the existing source-snapshot path, the job and response expose search mode and selected CPE families, API keys are not persisted, and zero CPE matches return an explicit no-match result without writing a snapshot, CVE, or ingestion job.
- [ ] **Step 2: Run the new tests to confirm failure.**

  Run: `.venv/bin/python -m pytest tests/unit/test_cve_technology_search.py tests/integration/test_v2_api.py -q`

  Expected: FAIL because `ingest_cve_search` currently requires only `technology` and returns no CPE resolution state.
- [ ] **Step 3: Wire the client result into `CKGApplication.ingest_cve_search`.** Require exactly one of `technology` or `cpe_name`; keep year validation and NVD-only source-kind validation; pass the exact search mode to the client; when metadata says `no_cpe_match`, return `{"status": "NO_CPE_MATCH", "query": ..., "cpe_families": []}` before snapshotting or creating a job; otherwise pass the aggregate through `ingest_structured_source` with `NVD_CVE_API_URL` as source URL and store technology, year bounds, search mode, CPE family strings, snapshot digest, and truncation flags in the job without the key.
- [ ] **Step 4: Keep GET semantics separate.** Add a regression assertion that `GET /cves?technology=...` searches repository data and does not invoke the NVD client.
- [ ] **Step 5: Run focused application/API tests.**

  Run: `.venv/bin/python -m pytest tests/unit/test_cve_technology_search.py tests/integration/test_v2_api.py -q`

  Expected: PASS; any network-dependent test remains mocked or explicitly opt-in.

### Task 3: Update the operator documentation and run regression suites

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture/03-ingestion.md`
- Test: `tests/unit/test_nvd_client.py`
- Test: `tests/unit/test_cve_technology_search.py`
- Test: `tests/unit/test_structured_vulnerability_ingestion.py`
- Test: `tests/integration/test_v2_api.py`

**Interfaces:**
- Consumes: the final CPE-first POST contract and existing local GET contract.
- Produces: documented examples distinguishing CPE-based NVD refresh from local graph search.

- [ ] **Step 1: Update both docs** to explain that POST resolves a technology to NVD CPE product families and retrieves CVEs using CPE matching, that callers may specify `cpe_name`, and that GET remains local; document no-match and truncation as explicit outcomes.
- [ ] **Step 2: Run the complete focused regression set.**

  Run: `.venv/bin/python -m pytest tests/unit/test_nvd_client.py tests/unit/test_cve_technology_search.py tests/unit/test_structured_vulnerability_ingestion.py tests/integration/test_v2_api.py -q`

  Expected: PASS, apart from documented external Neo4j opt-in skips.
- [ ] **Step 3: Inspect the final diff** for accidental edits outside the approved CKG client, API, tests, and docs; verify no secret or API key is added to fixtures or output.
