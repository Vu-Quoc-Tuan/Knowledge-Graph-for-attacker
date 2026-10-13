# CWE context API for DAST

## Purpose and boundary

Expose only the source-backed CWE and WSTG context DAST needs to propose a semantic scenario. CKG supplies planning context, not a target-specific executable plan. DAST remains responsible for endpoint profiles, authentication, bindings, review, execution, and interpreting observations.

## Endpoint

`GET /cwes/{id}/context` returns one compact JSON object for semantic scenario planning. The CWE ID must be an existing canonical `CWE` node; otherwise return 404. The endpoint is read-only and needs no pagination because CWE mapped WSTG strategies are a small set.

The response contains:

- `contract_version`: response contract version `1`.
- `cwe`: `id`, `name`, `description`, and `source` metadata (`MITRE CWE`, release, digest, retrieval time). Read these from the selected `CWEContentRevision`, not the mutable identity node. If the identity exists but no usable content revision exists, return null content fields and mark CWE content missing; never silently substitute a profile or description from another CWE.
- `wstg_methods`: a deterministically ordered list of explicitly linked methods. Each item includes WSTG ID/title, a curated method summary when the stored digest matches that exact summary, techniques, input surfaces, observable signals (the graph's oracle references), channels, and source metadata. The source metadata labels the OWASP WSTG reference and states `representation: ckg_curated_semantic_projection`, with URL, release, digest, evidence ID, and retrieval time. Only return a method when its WSTG case and source Evidence resolve. Never infer a CWE link by keyword or neighboring weakness.
- `availability`: per-component state (`available` or `missing`) for `cwe` and `wstg_methods`, plus a stable `missing_components` list.
- Raw PATT payloads are excluded because they are not needed to define a semantic scenario. A later DAST template-generation step can call the existing paginated `/cwes/{id}/payloads` endpoint; those values remain `reference_only` and `untested` unless separately validated.

This endpoint returns source context, not a generated scenario. No target URL, cookie, endpoint parameter, generated exploit, or execution result belongs in the response.

## Failure semantics and tests

Unknown CWE is 404; unexpected storage/backend failure remains an error, not an empty success response. DAST must treat an unreachable CKG or any `missing` component as incomplete context and surface that status to its user. It must not present a plan as WSTG-backed when that section is absent.

Example response:

```json
{
  "contract_version": 1,
  "cwe": {
    "id": "CWE-89",
    "name": "Improper Neutralization of Special Elements used in an SQL Command",
    "description": "...",
    "source": {
      "name": "MITRE CWE",
      "release": "4.20",
      "snapshot_digest": "sha256:...",
      "retrieved_at": "2026-09-20T00:00:00+00:00"
    }
  },
  "wstg_methods": [
    {
      "id": "WSTG-INPV-05",
      "title": "Testing for SQL Injection",
      "method_summary": "Verify whether user-supplied input alters SQL syntax execution through error, boolean differential, or time delays.",
      "techniques": [{"id": "TECH-BLIND", "name": "Blind"}],
      "input_surfaces": [{"id": "INPUT-QUERY-PARAMETER", "name": "Query Parameter"}],
      "observable_signals": [{"id": "ORACLE-RESPONSE", "name": "Response"}],
      "channels": [{"id": "CHANNEL-HTTP", "name": "HTTP"}],
      "source": {
        "name": "OWASP WSTG",
        "representation": "ckg_curated_semantic_projection",
        "url": "https://owasp.org/.../WSTG-INPV-05",
        "release": "v4.2",
        "snapshot_digest": "sha256:...",
        "evidence_id": "EVID-WSTG-...",
        "retrieved_at": "2026-09-20T00:00:00+00:00"
      }
    }
  ],
  "availability": {"cwe": "available", "wstg_methods": "available"},
  "missing_components": []
}
```

Test the application method and HTTP route on memory fixtures for full context, missing revision, missing WSTG, unknown CWE, source metadata, deterministic ordering, and omission of raw PATT payloads. Add a Neo4j-backed read-only smoke check where a local backend is available. No importer or graph schema change is required.
