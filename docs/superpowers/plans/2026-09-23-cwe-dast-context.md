# CWE DAST Context API Implementation Plan

> **For agentic workers:** This plan is being executed inline in the current session.

**Goal:** Add `GET /cwes/{id}/context` with only source-backed CWE and WSTG information needed to plan a semantic scenario.

**Architecture:** Add a read-only `CKGApplication.cwe_context` method in the existing API module and route the HTTP request through the established handler. Select the canonical CWE revision with `canonical_content_by_id` and follow only direct `TARGETS_WEAKNESS` mappings whose WSTG source Evidence resolves. Include the curated method summary only when its digest matches the stored projection. Keep payload references on the separate existing `/payloads` endpoint.

**Tech Stack:** Python, existing GraphRepository, standard-library HTTP handler, pytest.

## Global Constraints

- CWE content comes from the selected `CWEContentRevision` and retains source release, digest, and retrieval time.
- WSTG methods are included only for explicit CWE links and resolvable source provenance.
- Raw PATT payloads are omitted from scenario context; the separate payload API retains `reference_only` and `untested` statuses.
- Missing context is reported explicitly; unknown CWE returns 404.
- The endpoint accepts no target URL, cookies, or execution result.

---

### Task 1: Add the aggregated application response

**Files:**
- Modify: `src/ckg/api/main.py`
- Test: `tests/unit/test_cwe_dast_context_api.py`

**Interfaces:**
- Consumes: `canonical_content_by_id(repository, "CWE")`, graph nodes and source-verified WSTG edges.
- Produces: `CKGApplication.cwe_context(identifier) -> dict` with `contract_version`, CWE content/source, compact `wstg_methods`, and explicit availability.

- [x] Add fixtures for selected CWE revision, a mapped WSTG strategy, and its source Evidence.
- [x] Implement revision selection, direct-link traversal, deterministic WSTG serialization, and `availability`.
- [x] Cover missing content revision, missing WSTG, stale/unresolved WSTG provenance, unknown CWE, source metadata, and omission of PATT payload data.

### Task 2: Expose and verify the HTTP route

**Files:**
- Modify: `src/ckg/api/main.py`
- Test: `tests/unit/test_cwe_dast_context_api.py`
- Test: `tests/integration/test_v2_api.py`.

**Interfaces:**
- Consumes: `GET /cwes/{id}/context`.
- Produces: JSON from `CKGApplication.cwe_context`; existing HTTP error mapping for 400/404/backend failures.

- [x] Route context requests before the generic CWE profile/payload branches.
- [x] Verify successful JSON response and 404 for unknown CWE.
- [x] Run focused endpoint tests and the repository suite after the final compact response shape.

### Task 3: Document the consumer contract

**Files:**
- Modify: `README.md`.

- [x] Document response components and separate PATT retrieval.
- [x] State that WSTG links are explicit, `untested` PATT does not mean effective, and missing context must be surfaced by DAST.

## Self-review

- CWE revision, WSTG evidence/provenance, missing-data status, and HTTP errors each have implementation and verification steps.
- No graph schema, ingestion, target-scan, or execution behavior is added.
- The API reads only CWE-relevant WSTG edge types and fetches their endpoint nodes by ID; it does not export all graph nodes/edges for this request.
- Verification: focused API tests -> 11 passed; full suite excluding the offline wheel build test -> 291 passed, 14 skipped; read-only Neo4j check for CWE-89 returned the CWE source revision and WSTG-INPV-05 with a digest-matched curated summary, 3 techniques, 2 input surfaces, 2 observable signals, and 1 channel; `git diff --check` and `compileall` passed.
