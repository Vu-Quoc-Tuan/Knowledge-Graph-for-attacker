# CPE-First NVD Technology Search

## Status

Approved in conversation on 2026-09-23.

## Problem

`POST /ingest/cves/search` currently searches NVD CVE descriptions by the
technology string. Description matching can miss records whose affected
product is present in the CVE applicability data but not named in the prose,
and can include unrelated text matches. The graph's `GET /cves?technology=`
query is already local and product-backed; only the explicit NVD refresh path
changes.

## Goals

1. Resolve a technology query against NVD's CPE catalog before retrieving CVEs.
2. Fetch CVEs using NVD CVE API CPE criteria (`virtualMatchString` for a
   product family, or `cpeName` when the caller supplies a specific CPE).
3. Preserve the existing bounded year windows, pagination, record cap,
   snapshotting, and structured ingestion pipeline.
4. Deduplicate CVEs returned for multiple matching CPE families and expose
   which CPE identities were searched, plus candidate/result truncation.
5. Fail explicitly when CPE resolution has no usable match or NVD is
   unavailable; never silently fall back to description-only CVE keyword
   search.
6. Keep `GET /cves?technology=...` as a read-only search over the imported
   graph and leave Combined DAST integration out of scope.

## Design

The existing POST accepts `technology` as before and gains optional
`cpe_name` for an exact product CPE override. With `cpe_name`, the client
queries NVD CVEs using that CPE. With `technology`, the client queries NVD's
CPE API using the text only to resolve catalog candidates, groups candidates
by CPE part/vendor/product (so version-specific CPE rows do not trigger
duplicate searches), then queries NVD's CVE API with a broad CPE match string
for each product family. Search all valid families returned by CPE lookup in
stable order, up to 50 families; if the cap is reached, expose candidate
truncation. An exact `cpe_name` lets callers avoid broad candidate discovery.

Searches remain sequential and bounded. Publication date ranges are split into
windows no larger than 120 days; each page respects NVD's page limit; the
aggregate respects `max_records`; CVEs are deduplicated by CVE ID in stable
order. Candidate and result caps are surfaced as truncation metadata. The
aggregate response is passed to the existing snapshot/import pipeline only
after upstream retrieval succeeds.

The response and ingestion job add a compact resolution summary: search mode,
the CPE product families (or exact CPE) queried, candidate truncation, and CVE
truncation. API keys remain request headers and are never stored. An unresolved
technology returns a clear no-match result without writing an empty ingestion
snapshot or job. Upstream errors propagate through the existing API error path;
there is no weaker search fallback.

The source record continues to identify the NVD CVE API endpoint. The
ingestion job records the technology, year bounds, exact/family search mode,
queried CPE identities, and snapshot digest so the multi-query fetch remains
auditable without pretending that one URL represents every family request.

The implementation follows the NVD API 2.0 names: `/cpes/2.0` for CPE
resolution, `cpeName` for an exact CPE query, and `virtualMatchString` for a
broader applicability-criteria query. NVD requires date-filtered API requests
to use intervals no longer than 120 days. See the [NVD API documentation](https://nvd.nist.gov/developers/products), the [NVD Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities), and [NIST's API change notes](https://www.nist.gov/itl/nvd/nvd-news).

`GET /cves?technology=` continues to search graph Product nodes and return
affected product/version and source evidence. It does not contact NVD. This
change does not assert that a target is affected: callers still need a concrete
product/version comparison.

## Non-goals

- Connecting the CKG API to Combined DAST.
- Calling NVD on graph read requests.
- Claiming exact target applicability from a technology name alone.
- Changing CVE parsing, scenario generation, or execution behavior.

## Verification

Mocked client tests cover CPE lookup, product-family grouping, exact-CPE mode,
120-day windows, pagination, deduplication, truncation, no-match, and upstream
failure. Application tests prove no-match does not write graph state and a
successful CPE-based fetch still creates source-backed CVE graph records. The
focused test suite includes the NVD client, technology search, structured CVE
ingestion, and v2 API tests. Live NVD querying is optional and is not required
for the deterministic test suite.
